# cemtp-browser

A browser implementation of the Client-side Encrypted Mail Transfer Protocol (CEMTP) user client. Implements the [CEMTP 1.0 specification](https://gist.github.com/IAmJSD/eeedd125e9194a2a5bcbc10ef2f8ad7a). Note this does not support SMTP upgrades or pluggable transports since it is not supported by browsers.

Due to this, there is no logic for a server (the Node client should be used here), that is instead done by the Go and Node client/servers. This is useful for building clients.

This client relies on the openpgp library. Due to it being quite large, it is asynchronously imported. It is advised that whatever bundler you use can support this or else you might have a large bundle.

## User Client

The `UserClient` class is used to build a client which can be used to interact with the CEMTP protocol. To use it, first initialize it with the URL for the CEMTP endpoint, the email, and the password:
```js
const client = new UserClient("https://example.com/api/cemtp", "astrid@example.com", "password123");
```

From here, you can setup token authentication if needed by implementing token storage on a object:

```ts
export interface TokenStorage {
    // Gets the token. If null, will fall back to basic auth with the password hash.
    get: () => Promise<string | null>;

    // Sets the token.
    set: (token: string) => Promise<void>;
}
```

You can then set this with `setTokenStorage`. Note that if this is unset or `get` from it returns null for a request, it will revert to basic authentication where a SHA-512 password is used.

If you have additional private PGP keys that might be used for e-mails, you can also load the shielded private keys in with `addAdditionalPrivateKey`. This will then be used for mail decryption.

All other methods should within the class are directly mappable to a snake case version of what is in the spec. The arguments are laid out in a fairly sane way for all methods. One thing to note is anything using the me endpoint will contain its options (the parameter `options` for the me method or `meOptions` for any other function). This object contains the following which you can implement:

- `cacher`: When set, this cache will be tried before hitting the me endpoint. A implementation should use the following:
    ```ts
    export interface Cacher<T> {
        get: () => Promise<T | null>;
        set: (value: T) => Promise<void>;
        clear: () => Promise<void>;
    }
    ```
    In this case, `T` is the `DecryptedMeResponse` object.
- `prompt`: Used to prompt for the private key if private key is set to `null` (should return a shielded private PGP key) if `keyPrompt` is set to true, or a decryption key if it is set to false and the prompt strategy is sent by the mail server. The signature is `(keyPrompt: boolean) => Promise<string | ArrayBuffer>`. Throws `UnableToPrompt` if either of these cases are hit and this method is unset.

## Built-in Tools

There are several functions built in that can help with creating clients:

- `generateKeyPair(email: string, password: string): Promise<{ publicKey: string; encryptedPrivateKey: string; }>`: Generate a key pair containing both a public key and a encrypted private key encrypted with a SHA-256 hash of the password.
- `reencryptPrivateKey(privateKey: string, oldPassword: string, newPassword: string): Promise<string>`: SHA-256 hashes the old password for use as the decryption key, decrypt the private key with said hash, SHA-256 hashes the new password for use as the encryption key, encrypts the private key with said hash, returns the result.
