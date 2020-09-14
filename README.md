# Webauthn with Windows Hello support

## Prior art

 * https://github.com/strangerlabs/webauthn
 * https://github.com/wallix/webauthn
 * https://github.com/MicrosoftEdge/webauthnsample

Favicon made by [Pixel perfect](https://www.flaticon.com/authors/pixel-perfect "Pixel perfect") from [www.flaticon.com "Flaticon"](https://www.flaticon.com/)

## Dev notes

When testing you might end up creating a lot of keys for the same username,
making it difficult to know which one to use when logging in. This is what I
do to purge old keys.

Open up Windows Cmd in admin mode and run
`# certutil -csp NGC -key > keys.txt` to output a list of all keys to a text
file. `grep` the keys you want to delete and prepend each row with
`certutil -csp NGC -delkey`. Redirect all the output to a `.bat` file and run
that in the admin Cmd propmt again. The `.bat` file should just contain a
bunch of lines like these

```
certutil -csp NGC -delkey  S-1-5-21-3496337092-2350050884-2566336456-1001/46fc9ff0-f8c9-49ec-ac90-2b645f12ccec/FIDO_AUTHENTICATOR//49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_bada55c5e0bc91ac45bac8f9f2dff40b
certutil -csp NGC -delkey  S-1-5-21-3496337092-2350050884-2566336456-1001/46fc9ff0-f8c9-49ec-ac90-2b645f12ccec/FIDO_AUTHENTICATOR//49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_bada559f5a5510fffd4d76680cd6c369
certutil -csp NGC -delkey  S-1-5-21-3496337092-2350050884-2566336456-1001/46fc9ff0-f8c9-49ec-ac90-2b645f12ccec/FIDO_AUTHENTICATOR//49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_bada550ed601e9121bd1b8b40698a9cb
certutil -csp NGC -delkey  S-1-5-21-3496337092-2350050884-2566336456-1001/46fc9ff0-f8c9-49ec-ac90-2b645f12ccec/FIDO_AUTHENTICATOR//49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_bada55bc8bf4e92c755486caecb7b1ab
certutil -csp NGC -delkey  S-1-5-21-3496337092-2350050884-2566336456-1001/46fc9ff0-f8c9-49ec-ac90-2b645f12ccec/FIDO_AUTHENTICATOR//49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_bada550e4a46cd0223970b13e14dcdfc
certutil -csp NGC -delkey  S-1-5-21-3496337092-2350050884-2566336456-1001/46fc9ff0-f8c9-49ec-ac90-2b645f12ccec/FIDO_AUTHENTICATOR//49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_bada55c0dcef2445ffac2ce5062f433d
```
