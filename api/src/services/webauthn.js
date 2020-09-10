const crypto = require('crypto')
const cbor = require('cbor')

import base64url from 'base64url'
import { Webauthn } from 'src/lib/webauthn/Webauthn'
import {
  PublicKeyCredentialType,
  COSEAlgorithmIdentifier,
  AuthDataFlags,
  AttestationConveyancePreference,
} from 'src/lib/webauthn/Dictionaries'

const db = {}

function verifyAuthenticatorAttestationResponse(
  attestationObject,
  clientDataJSON
) {
  const attestationBuffer = base64url.toBuffer(attestationObject)
  const ctapCredResp = cbor.decodeFirstSync(attestationBuffer)
  const authenticatorKeyBuffer = Buffer.from(attestationObject, 'base64')
  const authenticatorKey = cbor.decodeFirstSync(authenticatorKeyBuffer)

  console.log('ctapCredResp', ctapCredResp)
  console.log('authenticatorKey', authenticatorKey)

  const authrDataStruct = Webauthn.parseCredAuthData(ctapCredResp.authData)

  console.log('authrDataStruct', authrDataStruct)

  if (!(authrDataStruct.flags & AuthDataFlags.USER_PRESENT)) {
    throw new Error('User was NOT presented durring authentication!')
  }

  const parsedCoseKey = Webauthn.parseCOSEKey(authrDataStruct.COSEPublicKey)

  const response = { verified: false }

  if (ctapCredResp.fmt === 'none') {
    response.verified = true
  } else if (ctapCredResp.fmt === 'fido-u2f') {
    const clientDataHash = Webauthn.hash(base64url.toBuffer(clientDataJSON))
    const publicKey = Webauthn.COSEECDHAtoPKCS(parsedCoseKey)
    const reservedByte = Buffer.from([0x00])
    const signatureBase = Buffer.concat([
      reservedByte,
      authrDataStruct.rpIdHash,
      clientDataHash,
      authrDataStruct.credID,
      publicKey,
    ])

    const PEMCertificate = Webauthn.ASN1toPEM(ctapCredResp.attStmt.x5c[0])
    const signature = ctapCredResp.attStmt.sig

    response.verified = Webauthn.verifySignature(
      signature,
      signatureBase,
      PEMCertificate
    )
    /*} else if (
    ctapCredResp.fmt === 'packed' &&
    ctapCredResp.attStmt.hasOwnProperty('x5c')
  ) {
    const clientDataHash = Webauthn.hash(
      base64url.toBuffer(clientDataJSON)
    )
    const signatureBase = Buffer.concat([
      ctapCredResp.authData,
      clientDataHash,
    ])

    const PEMCertificate = Webauthn.ASN1toPEM(ctapCredResp.attStmt.x5c[0])
    const signature = ctapCredResp.attStmt.sig

    const pem = Certificate.fromPEM(PEMCertificate)

    // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
    const aaguid_ext = pem.getExtension('1.3.6.1.4.1.45724.1.1.4')

    response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
      // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
      Webauthn.verifySignature(signature, signatureBase, PEMCertificate) &&
      // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
      pem.version == 3 &&
      // ISO 3166 valid country
      // TODO: Re-add this
      // typeof iso_3166_1.whereAlpha2(pem.subject.countryName) !== 'undefined' &&
      // Legal name of the Authenticator vendor (UTF8String)
      pem.subject.organizationName &&
      // Literal string “Authenticator Attestation” (UTF8String)
      pem.subject.organizationalUnitName === 'Authenticator Attestation' &&
      // A UTF8String of the vendor’s choosing
      pem.subject.commonName &&
      // The Basic Constraints extension MUST have the CA component set to false
      !pem.extensions.isCA &&
      // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
      // verify that the value of this extension matches the aaguid in authenticatorData.
      // The extension MUST NOT be marked as critical.
      (aaguid_ext != null
        ? authrDataStruct.hasOwnProperty('aaguid')
          ? !aaguid_ext.critical &&
            aaguid_ext.value.slice(2).equals(authrDataStruct.aaguid)
          : false
        : true)
*/
    // Self signed
  } else if (ctapCredResp.fmt === 'packed') {
    const clientDataHash = Webauthn.hash(base64url.toBuffer(clientDataJSON))
    const signatureBase = Buffer.concat([ctapCredResp.authData, clientDataHash])
    const publicKey = Webauthn.COSEECDHAtoPKCS(parsedCoseKey)
    const PEMCertificate = Webauthn.ASN1toPEM(publicKey)

    const {
      attStmt: { sig: signature, alg },
    } = ctapCredResp

    response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
      // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
      Webauthn.verifySignature(signature, signatureBase, PEMCertificate) &&
      alg === COSEAlgorithmIdentifier.ECDSA_w_SHA256
    /*} else if (ctapCredResp.fmt === 'android-safetynet') {
    let [
      header,
      payload,
      signature,
    ] = ctapCredResp.attStmt.response.toString('utf8').split('.')
    const signatureBase = Buffer.from([header, payload].join('.'))

    header = JSON.parse(base64url.decode(header))
    payload = JSON.parse(base64url.decode(payload))
    signature = base64url.toBuffer(signature)

    const PEMCertificate = Webauthn.ASN1toPEM(
      Buffer.from(header.x5c[0], 'base64')
    )

    const pem = Certificate.fromPEM(PEMCertificate)

    response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
      // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
      Webauthn.verifySignature(signature, signatureBase, PEMCertificate) &&
      // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
      pem.version == 3 &&
      pem.subject.commonName === 'attest.android.com'*/
  } else {
    throw new Error(`Unsupported attestation format: ${ctapCredResp.fmt}`)
  }

  if (response.verified) {
    response.authrInfo = {
      fmt: 'fido-u2f',
      publicKey: base64url.encode(JSON.stringify(parsedCoseKey)),
      counter: authrDataStruct.counter,
      credID: base64url.encode(authrDataStruct.credID),
    }
  }

  console.log('verify response', response)

  return response
}

export const prepCredentialCreation = ({ userName, displayName }) => {
  const challenge = base64url.encode(crypto.randomBytes(26))
  const userId = base64url.encode(crypto.randomBytes(16))

  if (db[userName] && db[userName].registered) {
    return {
      ok: false,
      message: `Username ${userName} already exists`,
    }
  }

  db[userName] = {
    name: displayName,
    registered: false,
    id: userId,
    authenticators: [],
    challenge,
  }

  const opts = {
    challenge,
    rp: {
      name: 'Tobbe Inc',
      id: 'localhost',
      icon: 'http://localhost:3000/favicon.png',
    },
    user: {
      id: userId,
      name: userName,
      displayName,
    },
    pubKeyCredParams: [
      {
        type: PublicKeyCredentialType.PUBLIC_KEY,
        alg: COSEAlgorithmIdentifier.ECDSA_w_SHA256,
      },
      {
        // Windows Hello
        type: PublicKeyCredentialType.PUBLIC_KEY,
        alg: COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_using_SHA_256,
      },
    ],
    attestation: AttestationConveyancePreference.NONE,
  }

  console.log('opts', opts)

  return {
    ok: true,
    opts,
  }
}

export const verifyAndRegister = ({
  userName,
  clientDataJSON,
  attestationObject,
}) => {
  if (!db[userName]) {
    return {
      ok: false,
      message: `No ongoing creation for user ${userName}`,
    }
  }

  let clientData

  try {
    const bufferarray = base64url.toBuffer(clientDataJSON)
    const json = String.fromCharCode.apply(null, new Uint8Array(bufferarray))

    console.log('json', json)
    clientData = JSON.parse(json)
  } catch (err) {
    console.log('err', err)
    return {
      ok: false,
      message: 'failed to decode client data',
    }
  }

  const { challenge, origin, type } = clientData

  console.log('challenge      ', challenge)
  console.log('saved challenge', db[userName].challenge)

  if (!challenge || challenge !== db[userName].challenge) {
    return {
      ok: false,
      message: 'challenge missmatch',
    }
  }

  if (!origin || origin !== 'http://localhost:8910') {
    return {
      ok: false,
      message: 'origin missmatch',
    }
  }

  if (!type || type !== 'webauthn.create') {
    return {
      ok: false,
      message: 'wrong type',
    }
  }

  let result

  if (attestationObject !== undefined) {
    result = verifyAuthenticatorAttestationResponse(
      attestationObject,
      clientDataJSON
    )

    if (result.verified) {
      db[userName].authenticators.push(result.authrInfo)
      db[userName].registered = true
    }
  }

  return {
    ok: true,
  }
}
