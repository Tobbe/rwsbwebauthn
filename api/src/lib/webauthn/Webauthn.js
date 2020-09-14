import * as crypto from 'crypto'
import * as cbor from 'cbor'

const {
  AuthDataFlags,
  COSEAlgorithmIdentifier,
  COSEKeyType,
} = require('./Dictionaries')

export class Webauthn {
  static hash(alg, data) {
    return crypto.createHash(alg).update(data).digest()
  }

  static verifySignature(signature, data, publicKey) {
    if (!publicKey.kty) {
      console.error('wrong key type')
      return
    }

    console.log('verifySignature publicKey', publicKey)

    const pemPublicKey =
      publicKey.kty === COSEKeyType.EC2
        ? this.ASN1toPEM(this.COSEECDHAtoPKCS(publicKey))
        : this.RSAPublicKeyToPEM(publicKey)

    console.log('pemPublicKey', pemPublicKey)

    const verify =
      publicKey.kty === COSEKeyType.RSA
        ? crypto.createVerify('RSA-SHA256')
        : crypto.createVerify('sha256')

    return verify.update(data).verify(pemPublicKey, signature)
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
  // https://stackoverflow.com/questions/54045911/webauthn-byte-length-of-the-credential-public-key
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
        flagsBuf,
        counter,
        counterBuf,
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
      flagsBuf,
      counter,
      counterBuf,
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
      coseKey.kty === COSEKeyType.EC2 &&
      coseKey.alg === COSEAlgorithmIdentifier.ECDSA_w_SHA256
    ) {
      coseKey.x = coseStruct.get(-2)
      coseKey.y = coseStruct.get(-3)
    } else if (
      coseKey.kty === COSEKeyType.RSA &&
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

  /**
   * Convert binary certificate or public key to an OpenSSL-compatible PEM text
   * format.
   */
  static ASN1toPEM(pkBuffer) {
    if (!Buffer.isBuffer(pkBuffer)) {
      throw new Error('ASN1toPEM: pkBuffer must be Buffer.')
    }

    let type
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
      /*
        If needed, we encode rawpublic key to ASN structure, adding metadata:
        SEQUENCE {
          SEQUENCE {
              OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
              OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
          }
          BITSTRING <raw public key>
        }
        Luckily, to do that, we just need to prefix it with constant 26 bytes
        (metadata is constant).
      */
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

  /**
   * Convert binary RSA public key to an OpenSSL-compatible PEM text format.
   *
   * @link https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
   * @link https://geeklaunch.net/blog/what-does-my-rsa-public-key-actually-mean/
   */
  static RSAPublicKeyToPEM(publicKey) {
    if (!Buffer.isBuffer(publicKey.n)) {
      throw new Error('RSAPublicKeyToPEM: publicKey.n must be a buffer.')
    }

    if (publicKey.n.length !== 256) {
      throw new Error('RSAPublicKey Wrong key modulus length')
    }

    if (publicKey.e.length !== 3) {
      throw new Error('RSAPublicKey Wrong key exponent length')
    }

    let type = 'PUBLIC KEY'

    /*
      Example 256 byte RSA public key in DER encoded ASN.1 format

      30 82 01 22                          ; SEQUENCE (30), 2 length bytes (82), length=290 bytes (0x0122)
         30 0d                             ; SEQUENCE (30), length=13 (0x0d)
            06 09                          ; OBJECT_IDENTIFIER (06), length=9 (0x09)
               2a 86 48 86 f7 0d 01 01 01  ; 1.2.840.113549.1.1.1
            05 00                          ; NULL (05), length=0 (0x00)
         03 82 01 0f                       ; BIT_STRING (03), 2 length bytes (82), length=271 bytes (0x010f)
            00                             ; 0 unused bits
            30 82 01 0a                    ; SEQUENCE, length=266
               02 82 01 01                 ; INTEGER, length=257  -- this is the modulus of the key
                  00                       ; positive integer
                  c4 d1 70 a2 1c 45 9c 86  c2 f7 6c ef 6e 04 65 f7
                  9c a1 25 06 5b f0 e5 bd  5c d6 ec b9 9b e4 1b 56
                  fa b8 53 d6 b2 de aa 84  ed 8b bd 64 69 f0 3a 96
                  14 0b 1c a8 52 eb fc fb  ce 74 dc b6 3a 52 f8 fa
                  e8 ce 59 0c de 47 7b 65  95 3b 1a 1c 4a 05 0e 76
                  6b c0 c4 a3 ea b4 e6 84  58 0d 57 6b a1 be 0e 32
                  84 48 e2 cd 72 ee 11 2c  ed 37 d3 a7 4a 38 2f d6
                  4e 33 f5 6f 65 00 a8 a0  df e4 c8 e1 57 c2 97 9c
                  ae 41 da 69 8a f3 5b f6  4f f9 60 5a 75 07 c7 7e
                  a7 c6 00 80 ef 31 fd d2  02 53 bf 9b e6 c4 97 84
                  5c 04 ec a6 0a ae 6a 83  36 8d e3 2b 26 d0 ce 06
                  24 3e b8 c9 18 e3 ba 5a  eb f6 67 5e 2c 6c 6a 2d
                  34 1c 42 d1 b9 be c6 23  d4 7c ac 47 46 18 b9 98
                  09 08 11 de 51 40 19 bc  c8 cd 83 e8 d5 37 20 2f
                  ca 69 c1 42 8e e8 95 18  d0 79 9f 84 8a 6c 64 03
                  aa 6b 66 9b 5d 18 a5 1d  58 0f 95 e6 a8 04 1a 75
               02 03                       ; INTEGER, length=3  -- this is the exponent of the key
                  01 00 01
    */

    const pkBuffer = Buffer.concat([
      Buffer.from(
        '30820122300d06092a864886f70d01010105000382010f003082010a0282010100',
        'hex'
      ),
      publicKey.n,
      Buffer.from('0203', 'hex'),
      publicKey.e
    ])

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
