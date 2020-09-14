/**
 * UserVerificationRequirement
 * @link https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement
 */
export const UserVerificationRequirement = {
  REQUIRED: 'required',
  PREFERRED: 'preferred',
  DISCOURAGED: 'discouraged',
}

/**
 * AuthenticatorAttachment
 * @link https://www.w3.org/TR/webauthn/#enumdef-authenticatorattachment
 */
export const AuthenticatorAttachment = {
  PLATFORM: 'platform',
  CROSS_PLATFORM: 'cross-platform',
}

/**
 * AttestationConveyancePreference
 * @link https://www.w3.org/TR/webauthn/#attestation-convey
 */
export const AttestationConveyancePreference = {
  NONE: 'none',
  DIRECT: 'direct',
  INDIRECT: 'indirect',
}

/**
 * PublicKeyCredentialType
 * @link https://www.w3.org/TR/webauthn/#credentialType
 */
export const PublicKeyCredentialType = {
  PUBLIC_KEY: 'public-key',
}

/**
 * AuthenticatorTransport
 * @link https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
 */
export const AuthenticatorTransport = {
  USB: 'usb',
  NFC: 'nfc',
  BLE: 'ble',
  INTERNAL: 'internal',
}

/**
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 * @link https://www.w3.org/TR/webauthn/#typedefdef-cosealgorithmidentifier
 */
export const COSEAlgorithmIdentifier = {
  ECDSA_w_SHA256: -7,
  RSASSA_PKCS1_v1_5_using_SHA_256: -257,
}

export const COSEKeyType = {
  EC2: 2,
  RSA: 3,
}

/**
 * @link https://www.w3.org/TR/webauthn/#table-authData
 */
export const AuthDataFlags = {
  USER_PRESENT: 0b00000001,
  USER_VERIFIED: 0b00000100,
  ATTESTED_CREDENTIAL_DATA_INCLUDED: 0b01000000,
  EXTENSION_DATA_INCLUDED: 0b10000000,
}
