import base64url from 'base64url'
import { useApolloClient } from '@redwoodjs/web'

const PREP_MUTATION = gql`
  mutation PrepMutation($userName: String!, $displayName: String!) {
    prepResponse: prepCredentialCreation(
      userName: $userName
      displayName: $displayName
    ) {
      ok
      message
      opts {
        challenge
        rp {
          name
          id
        }
        user {
          id
          name
          displayName
        }
        pubKeyCredParams {
          type
          alg
        }
      }
    }
  }
`

const VERIFY_AND_REGISTER_MUTATION = gql`
  mutation VerifyAndRegistereMutation(
    $userName: String!
    $attestationObject: String!
    $clientDataJSON: String!
  ) {
    verifyAndRegisterResponse: verifyAndRegister(
      userName: $userName
      attestationObject: $attestationObject
      clientDataJSON: $clientDataJSON
    ) {
      ok
      message
    }
  }
`

const HomePage = () => {
  const apolloClient = useApolloClient()
  const [data, setData] = React.useState()
  const [error, setError] = React.useState()
  const [showCreationError, setShowCreationError] = React.useState(false)
  const [userName, setUserName] = React.useState('tobbelundberg')

  const prepCredentialCreation = async () => {
    try {
      const { data } = await apolloClient.mutate({
        mutation: PREP_MUTATION,
        variables: {
          userName,
          displayName: 'Tobbe Lundberg',
        },
      })

      return data.prepResponse
    } catch (err) {
      return {
        ok: false,
        message: 'query error ' + err,
      }
    }
  }

  const verifyAndRegister = (attestation) => {
    apolloClient
      .mutate({
        mutation: VERIFY_AND_REGISTER_MUTATION,
        variables: {
          userName,
          clientDataJSON: base64url.encode(attestation.response.clientDataJSON),
          attestationObject: base64url.encode(
            attestation.response.attestationObject
          ),
        },
      })
      .then(({ data }) => {
        console.log('data', data)
      })
      .catch((err) => {
        console.log('err', err)
      })
  }

  const signup = async () => {
    const { ok, message, opts } = await prepCredentialCreation()

    if (!ok) {
      console.log(message)
      setError(message)
      return
    }

    setData(opts)

    opts.challenge = base64url.toBuffer(opts.challenge)
    opts.user.id = base64url.toBuffer(opts.user.id)
    console.log('opts', opts)

    navigator.credentials
      .create({ publicKey: opts })
      .then((attestation) => {
        // Send new credential info to server for verification and registration.
        console.log('attestation', attestation)
        verifyAndRegister(attestation)
      })
      .catch((err) => {
        console.log('create err', err)
        console.log('You must setup 2FA to be able to use this service')
        setShowCreationError(true)
        setError(err)
      })
  }

  return (
    <>
      <h1>HomePage</h1>
      <button onClick={signup}>Create Credentials</button>

      {showCreationError && (
        <div>
          <p>You must setup 2FA to be able to use this service</p>
        </div>
      )}

      {error && (
        <div style={{ color: 'red' }}>
          <p>Error :(</p>
          <pre>{JSON.stringify(error, null, '  ')}</pre>
        </div>
      )}

      {data && (
        <pre>
          <code>{JSON.stringify(data, null, '  ')}</code>
        </pre>
      )}
    </>
  )
}

export default HomePage
