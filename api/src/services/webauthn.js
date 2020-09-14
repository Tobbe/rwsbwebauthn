const crypto = require('crypto')
const cbor = require('cbor')

import base64url from 'base64url'
import { db } from 'src/lib/db'
import { Webauthn } from 'src/lib/webauthn/Webauthn'
import {
  PublicKeyCredentialType,
  COSEAlgorithmIdentifier,
  AuthDataFlags,
  AttestationConveyancePreference,
  UserVerificationRequirement,
} from 'src/lib/webauthn/Dictionaries'

function verifyAuthenticatorAttestationResponse(
  attestationObject,
  clientDataJSON
) {
  const attestationBuffer = base64url.toBuffer(attestationObject)
  const ctapCredResp = cbor.decodeFirstSync(attestationBuffer)

  console.log('ctapCredResp', ctapCredResp)

  const authrDataStruct = Webauthn.parseCredAuthData(ctapCredResp.authData)

  console.log('authrDataStruct', authrDataStruct)

  if (!(authrDataStruct.flags & AuthDataFlags.USER_PRESENT)) {
    throw new Error('User was NOT presented durring authentication!')
  }

  const parsedCoseKey = Webauthn.parseCOSEKey(authrDataStruct.COSEPublicKey)
  console.log('parsedCoseKey', parsedCoseKey)

  const response = { verified: false }

  if (ctapCredResp.fmt === 'none') {
    response.verified = true
  } else if (ctapCredResp.fmt === 'fido-u2f') {
    const clientDataHash = Webauthn.hash(
      'sha256',
      base64url.toBuffer(clientDataJSON)
    )
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
    const clientDataHash = Webauthn.hash('sha256',
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
    const clientDataHash = Webauthn.hash(
      'sha256',
      base64url.toBuffer(clientDataJSON)
    )
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
      fmt: 'fido-u2f', // TODO: Always? Really?
      publicKey: parsedCoseKey,
      counter: authrDataStruct.counter,
      credID: base64url.encode(authrDataStruct.credID),
    }
  }

  console.log('verify response', response)

  return response
}

export const prepCredentialCreation = async ({ userName, displayName }) => {
  const challenge = base64url.encode(crypto.randomBytes(26))
  const userIdBuf = crypto.randomBytes(16)
  // On a production system you don't want to do this. I just do it here to
  // make it easier to find these keys, where this becomes part of the system
  // key name
  userIdBuf[0] = 0xba
  userIdBuf[1] = 0xda
  userIdBuf[2] = 0x55
  const userId = base64url.encode(userIdBuf)

  let dbUser = await db.user.findOne({ where: { userName } })

  if (dbUser?.registered) {
    return {
      ok: false,
      message: `Username ${userName} already exists`,
    }
  }

  dbUser = await db.user.upsert({
    where: { userName },
    create: {
      userName,
      name: displayName,
      registered: false,
      id: userId,
      authenticators: [],
      challenge,
    },
    update: {
      userName,
      name: displayName,
      registered: false,
      id: userId,
      authenticators: [],
      challenge,
    },
  })

  const opts = {
    challenge,
    rp: {
      name: 'Tobbe Inc',
      id: process.env.RP_HOST,
      icon: 'https://rwsbwebauthn.netlify.app/favicon.png',
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

export const verifyAndRegister = async ({
  userName,
  clientDataJSON,
  attestationObject,
  id,
}) => {
  let dbUser = await db.user.findOne({ where: { userName } })

  if (!dbUser || !dbUser.challenge) {
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
  console.log('saved challenge', dbUser.challenge)
  console.log('id', id)
  if (dbUser.authenticators && dbUser.authenticators[0]) {
    console.log('saved id', dbUser.authenticators[0].credID)
  }

  if (!challenge || challenge !== dbUser.challenge) {
    return {
      ok: false,
      message: 'challenge missmatch',
    }
  }

  if (origin !== 'http://localhost:8910' && origin !== 'https://rwsbwebauthn.netlify.app') {
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
      const authenticators = dbUser.authenticators
      authenticators.push(result.authrInfo)
      await db.user.update({
        data: {
          ...dbUser,
          registered: true,
          authenticators,
        },
        where: { userName },
      })
    }
  }

  console.log('===================================')
  console.log('== Registration done             ==')
  console.log('===================================')

  return {
    ok: true,
  }
}

export const prepCredentialGet = async ({ userName }) => {
  const challenge = base64url.encode(crypto.randomBytes(26))

  let dbUser = await db.user.findOne({ where: { userName } })

  if (!dbUser || !dbUser.registered) {
    return {
      ok: false,
      message: 'user not registered',
    }
  }

  console.log('get-challenge', challenge)

  await db.user.update({
    data: { ...dbUser, challenge },
    where: { userName },
  })

  return {
    ok: true,
    opts: {
      challenge,
      // allowCredentials: [{
      //   type: PublicKeyCredentialType.PUBLIC_KEY,

      // }]
      userVerification: UserVerificationRequirement.DISCOURAGED,
    },
  }
}

export const verifyAndLogin = async ({
  userName,
  authenticatorData,
  clientDataJSON,
  signature,
}) => {
  let dbUser = await db.user.findOne({ where: { userName } })

  if (!dbUser?.registered) {
    return {
      ok: false,
      message: 'user not registered',
    }
  }

  console.log('dbUser', dbUser)

  let clientData
  let clientDataJSONStr

  try {
    const bufferarray = base64url.toBuffer(clientDataJSON)
    const json = String.fromCharCode.apply(null, new Uint8Array(bufferarray))
    clientDataJSONStr = json

    console.log('json', json)
    clientData = JSON.parse(json)
  } catch (err) {
    console.log('err', err)
    return {
      ok: false,
      message: 'failed to decode client data',
    }
  }

  console.log('clientData', clientData)
  console.log('authenticatorData', authenticatorData)

  const authDataBuffer = base64url.toBuffer(authenticatorData)
  const authrDataStruct = Webauthn.parseCredAuthData(authDataBuffer)

  console.log('authDataBuffer', authenticatorData)
  console.log('authDataB64', Buffer.from(authenticatorData, 'base64'))

  console.log('authrData', authrDataStruct)
  console.log('rpId', base64url.encode(authrDataStruct.rpIdHash))

  // TODO: Check proper counter
  if (authrDataStruct.counter <= /*dbUser...*/ 0) {
    return {
      ok: false,
      message: 'possibly cloned authenticator',
    }
  }

  const sigBuffer = base64url.toBuffer(signature)
  console.log('sigBuffer', sigBuffer)

  // TODO: Support more keys by looping over all of them
  const publicKey = dbUser.authenticators[0].publicKey

  //Step 11: Verify that the rpIdHash in authData is the SHA-256 hash of the
  //RP ID expected by the Relying Party.
  if (!authrDataStruct.rpIdHash.equals(Webauthn.hash('sha256', process.env.RP_HOST))) {
    throw new Error(
      'RPID hash does not match expected value: sha256(' + hostname + ')'
    )
  }

  const clientDataHash = Webauthn.hash(
    'sha256',
    Buffer.from(clientDataJSON, 'base64')
    // base64url.toBuffer(clientDataJSON)
  )

  // TODO: Try to just use authenticatorData
  const signatureBase = Buffer.concat([
    // authrDataStruct.rpIdHash,
    // authrDataStruct.flagsBuf,
    // authrDataStruct.counterBuf,
    // Buffer.from(authenticatorData, 'base64'),
    authDataBuffer,
    clientDataHash,
  ])

  const verified = Webauthn.verifySignature(sigBuffer, signatureBase, publicKey)

  // `signature` is authenticatorData concatinated with clientDataHash and
  // then encrypted with the private key.

  console.log('verified', verified)

  const pemPublicKey = Webauthn.RSAPublicKeyToPEM(publicKey)

  console.log(
    'inline verify',
    crypto
      .createVerify('RSA-SHA256')
      .update(authDataBuffer)
      .update(crypto.createHash('sha256').update(clientDataJSONStr).digest())
      .verify(pemPublicKey, sigBuffer)
  )

  if (!verified) {
    return {
      ok: false,
      message: 'Could not verify signature',
    }
  }

  return {
    ok: true,
  }
}
