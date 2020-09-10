export const schema = gql`
  type RelayingParty {
    name: String!
    id: String!
  }

  type User {
    id: ID!
    name: String!
    displayName: String!
  }

  type PubKeyCredParams {
    type: String!
    alg: Int!
  }

  type PublicKeyCredentialCreationOptions {
    challenge: String!
    rp: RelayingParty!
    user: User!
    pubKeyCredParams: [PubKeyCredParams!]!
  }

  type VerifyAndRegisterResponse {
    ok: Boolean!
    message: String
  }

  type CredentialCreationResponse {
    ok: Boolean!
    message: String
    opts: PublicKeyCredentialCreationOptions
  }

  type Mutation {
    prepCredentialCreation(
      userName: String!
      displayName: String!
    ): CredentialCreationResponse!
    verifyAndRegister(
      userName: String!
      attestationObject: String!
      clientDataJSON: String!
    ): VerifyAndRegisterResponse!
  }
`
