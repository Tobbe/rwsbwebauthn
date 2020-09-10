import * as cbor from 'cbor'
const { AuthDataFlags, COSEAlgorithmIdentifier } = require('./Dictionaries')

export class Webauthn {
  static hash(data) {
    return crypto.createHash('sha256').update(data).digest()
  }

  static verifySignature(signature, data, publicKey) {
    return crypto
      .createVerify('SHA256')
      .update(data)
      .verify(publicKey, signature)
  }

  static parseGetAssertAuthData(buffer) {
    const rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)

    const flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)

    const flags = flagsBuf[0]

    const counterBuf = buffer.slice(0, 4)
    buffer = buffer.slice(4)

    const counter = counterBuf.readUInt32BE(0)

    return { rpIdHash, flagsBuf, flags, counter, counterBuf }
  }

  // https://www.w3.org/TR/webauthn/#sctn-attestation
  static parseCredAuthData(buffer) {
    const rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)

    const flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)

    const flags = flagsBuf[0]

    const counterBuf = buffer.slice(0, 4)
    buffer = buffer.slice(4)

    const counter = counterBuf.readUInt32BE(0)

    if (!(flags & AuthDataFlags.ATTESTED_CREDENTIAL_DATA_INCLUDED)) {
      return {
        rpIdHash,
        flags,
        counter,
      }
    }

    const aaguid = buffer.slice(0, 16)
    buffer = buffer.slice(16)

    const credIDLenBuf = buffer.slice(0, 2)
    buffer = buffer.slice(2)

    const credIDLen = credIDLenBuf.readUInt16BE(0)

    const credID = buffer.slice(0, credIDLen)
    buffer = buffer.slice(credIDLen)

    const COSEPublicKey = buffer

    return {
      rpIdHash,
      flags,
      counter,
      aaguid,
      credID,
      COSEPublicKey,
    }
  }

  // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
  static parseCOSEKey(COSEPublicKey) {
    const coseStruct = cbor.decodeFirstSync(COSEPublicKey)
    const coseKey = {
      kty: coseStruct.get(1),
      alg: coseStruct.get(3),
    }

    if (
      coseKey.kty === 2 &&
      coseKey.alg === COSEAlgorithmIdentifier.ECDSA_w_SHA256
    ) {
      coseKey.x = coseStruct.get(-2)
      coseKey.y = coseStruct.get(-3)
    } else if (
      coseKey.kty === 3 &&
      coseKey.alg === COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_using_SHA_256
    ) {
      coseKey.n = coseStruct.get(-1)
      coseKey.e = coseStruct.get(-2)
    }

    return coseKey
  }

  // https://tools.ietf.org/html/rfc8152#section-13.1.1
  //
  // +-------+------+-------+--------+-----------------------------------+
  // | Key   | Name | Label | CBOR   | Description                       |
  // | Type  |      |       | Type   |                                   |
  // +-------+------+-------+--------+-----------------------------------+
  // | 2     | crv  | -1    | int /  | EC identifier - Taken from the    |
  // |       |      |       | tstr   | "COSE Elliptic Curves" registry   |
  // | 2     | x    | -2    | bstr   | x-coordinate                      |
  // | 2     | y    | -3    | bstr / | y-coordinate                      |
  // |       |      |       | bool   |                                   |
  // | 2     | d    | -4    | bstr   | Private key                       |
  // +-------+------+-------+--------+-----------------------------------+
  static COSEECDHAtoPKCS(parsedCoseKey) {
    const tag = Buffer.from([0x04])

    return Buffer.concat([tag, parsedCoseKey.x, parsedCoseKey.y])
  }

  static ASN1toPEM(pkBuffer) {
    if (!Buffer.isBuffer(pkBuffer)) {
      throw new Error('ASN1toPEM: pkBuffer must be Buffer.')
    }

    let type
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
      pkBuffer = Buffer.concat([
        new Buffer.from(
          '3059301306072a8648ce3d020106082a8648ce3d030107034200',
          'hex'
        ),
        pkBuffer,
      ])

      type = 'PUBLIC KEY'
    } else {
      type = 'CERTIFICATE'
    }

    const b64cert = pkBuffer.toString('base64')

    let PEMKey = ''
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
      const start = 64 * i
      PEMKey += b64cert.substr(start, 64) + '\n'
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`
    return PEMKey
  }
}
