import base64url from 'base64url'
import { useApolloClient } from '@redwoodjs/web'

const PREP_CREATE_MUTATION = gql`
  mutation PrepCreateMutation($userName: String!, $displayName: String!) {
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
  mutation VerifyAndRegisterMutation(
    $userName: String!
    $attestationObject: String!
    $clientDataJSON: String!
    $id: String!
  ) {
    verifyAndRegisterResponse: verifyAndRegister(
      userName: $userName
      attestationObject: $attestationObject
      clientDataJSON: $clientDataJSON
      id: $id
    ) {
      ok
      message
    }
  }
`

const PREP_GET_MUTATION = gql`
  mutation PrepGetMutation($userName: String!) {
    prepResponse: prepCredentialGet(userName: $userName) {
      ok
      message
      opts {
        challenge
      }
    }
  }
`

const VERIFY_AND_LOGIN_MUTATION = gql`
  mutation VerifyAndLoginMutation(
    $userName: String!
    $authenticatorData: String!
    $clientDataJSON: String!
    $signature: String!
  ) {
    verifyAndLoginResponse: verifyAndLogin(
      userName: $userName
      authenticatorData: $authenticatorData
      clientDataJSON: $clientDataJSON
      signature: $signature
    ) {
      ok
      message
    }
  }
`

const HomePage = () => {
  const apolloClient = useApolloClient()
  const [error, setError] = React.useState()
  const [requiredError, setRequiredError] = React.useState(false)
  const [showCreationError, setShowCreationError] = React.useState(false)
  const [showLoginError, setShowLoginError] = React.useState(false)
  const [userName, setUserName] = React.useState('')
  const [registered, setRegistered] = React.useState('')
  const [loggedIn, setLoggedIn] = React.useState(false)

  const prepCredentialCreation = async () => {
    try {
      const { data } = await apolloClient.mutate({
        mutation: PREP_CREATE_MUTATION,
        variables: {
          userName,
          displayName: userName,
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
          id: attestation.id,
        },
      })
      .then(({ data }) => {
        console.log('data', data)

        if (data.verifyAndRegisterResponse.ok) {
          setRegistered(userName)
        }

        console.log('===================================')
        console.log('== Registration done             ==')
        console.log('===================================')
      })
      .catch((err) => {
        console.log('err', err)
      })
  }

  const prepCredentialGet = async () => {
    try {
      const { data } = await apolloClient.mutate({
        mutation: PREP_GET_MUTATION,
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

  const verifyAndLogin = (credential) => {
    apolloClient
      .mutate({
        mutation: VERIFY_AND_LOGIN_MUTATION,
        variables: {
          userName,
          authenticatorData: base64url.encode(
            credential.response.authenticatorData
          ),
          clientDataJSON: base64url.encode(credential.response.clientDataJSON),
          signature: base64url.encode(credential.response.signature),
        },
      })
      .then(({ data }) => {
        console.log('data', data)
        if (data.verifyAndLoginResponse.ok) {
          setLoggedIn(userName)
        }
      })
      .catch((err) => {
        console.log('err', err)
      })
  }

  const signup = async () => {
    if (!userName) {
      setRequiredError(true)
      return
    }

    setError('')
    setRegistered('')
    setLoggedIn('')

    const { ok, message, opts } = await prepCredentialCreation()

    if (!ok) {
      console.log(message)
      setError(message)
      return
    }

    opts.challenge = base64url.toBuffer(opts.challenge)
    opts.user.id = base64url.toBuffer(opts.user.id)
    console.log('signup opts', opts)

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

  const login = async () => {
    if (!userName) {
      setRequiredError(true)
      return
    }

    setError('')
    const { ok, message, opts } = await prepCredentialGet()

    if (!ok) {
      console.log(message)
      setError(message)
      return
    }

    console.log('login opts', opts)

    opts.challenge = base64url.toBuffer(opts.challenge)

    navigator.credentials
      .get({ publicKey: opts })
      .then((credential) => {
        console.log('credential', credential)
        verifyAndLogin(credential)
      })
      .catch((err) => {
        console.log('get err', err)
        setShowLoginError(true)
        setError(err)
      })
  }

  return (
    <>
      <h1>WebAuthn demo</h1>
      <label htmlFor="username">
        Username
        <input
          type="text"
          id="username"
          name="username"
          value={userName}
          onChange={(e) => {
            setRequiredError(false)
            setUserName(e.target.value)
          }}
        />
        {requiredError && <p className="error">Username is required</p>}
      </label>

      <button onClick={signup}>Signup</button>
      <button onClick={login}>Login</button>

      {showCreationError && (
        <div>
          <p>You must setup 2FA to be able to use this service</p>
        </div>
      )}

      {showLoginError && (
        <div>
          <p>Could not log you in</p>
        </div>
      )}

      {error && (
        <div className="error">
          <p>Error :(</p>
          <pre>{JSON.stringify(error, null, '  ')}</pre>
        </div>
      )}

      {registered && (
        <div>
          <p>You have successfully registered an account for user {registered}</p>
          <p>Try clicking the "Login" button</p>
        </div>
      )}

      {loggedIn && (
        <div>
          <p>You have successfully logged in as {loggedIn}</p>
          <p>Here is some secret text you need to be logged in to see</p>
        </div>
      )}
    </>
  )
}

export default HomePage
