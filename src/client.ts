// JS implementation of a Client-side Encrypted Mail Transfer Protocol (CEMTP) user client.
// Copyright (C) 2023 Web Scale Software Ltd. Licensed under the MIT license.
// Written By: Astrid Gealer <astrid@webscalesoftware.ltd>

// Import the error things we need.
import {
    handleError, ResponseNonSpecCompliant,
    UnableToPrompt, PromptResponseError,
} from './errors';

// Get the openpgp types.
import type { PrivateKey, PublicKey } from 'openpgp';

// Get things shared across parts of the library.
import { openpgpImport, base64ToBufferAsync } from './shared';

// Defines the options to send a email.
type EncryptedSendEmailOptions = {
    encrypted: true;
    to: string;
    publicKey: string;
    from: string;
    subject: string;
    otherHeaders: {[key: string]: string};
    body: ArrayBuffer;
};
type UnencryptedSendEmailOptions = {
    encrypted: false;
    headers: {[key: string]: string};
    body: ArrayBuffer;
};
export type SendEmailUserOptions = EncryptedSendEmailOptions | UnencryptedSendEmailOptions;

// Defines the encrypted version of the folder part of the me response.
export type DecryptedFolder = {
    folderId: string | number;
    folderName: string;
    count: number;
};

// Defines the decrypted version of the me response.
export type DecryptedMeResponse = {
    name: string;
    emails: string[];
    pgpPublicKey: string;
    pgpPrivateKey: string;
    folders: DecryptedFolder[];
};

// Used to cache commonly used values such as the me response.
export interface Cacher<T> {
    get: () => Promise<T | null>;
    set: (value: T) => Promise<void>;
    clear: () => Promise<void>;
}

// Used to store the token.
export interface TokenStorage {
    // Gets the token. If null, will fall back to basic auth with the password hash.
    get: () => Promise<string | null>;

    // Sets the token.
    set: (token: string) => Promise<void>;
}

// Defines a method to prompt for a password or key. If keyPrompt is true, the prompt
// should be for the private keys contents. If false, it should be for the password.
export type PromptHandler = (keyPrompt: boolean) => Promise<string | ArrayBuffer>;

// The default prompt handler. Just errors.
const defaultPromptHn: PromptHandler = () => {
    throw new UnableToPrompt();
};

// Used for any request that might hit the me endpoint.
export type MeOptions = {
    // If the cacher is present, it will be used to cache the me response.
    cacher?: Cacher<DecryptedMeResponse>;

    // If the prompt method is present, it will be used to prompt for a password if
    // the strategy isn't password. Will raise UnableToPrompt if not present
    // and the strategy isn't password.
    prompt?: PromptHandler;
};

interface PasswordStrategy {
    type: 'password';
}

interface PromptStrategy {
    type: 'prompt';
    sha256: boolean;
}

interface EncryptedPGPKey {
    encrypted_key: string;
    strategy: PasswordStrategy | PromptStrategy;
}

const processEncryptedPgpKey = (body: any): EncryptedPGPKey | null => {
    // Null body is allowed as per the spec.
    if (!body) return null;

    // This has to be a object otherwise or it's not spec compliant.
    if (typeof body !== 'object') {
        throw new ResponseNonSpecCompliant('encrypted_pgp_private_key was not an object');
    }

    // Assert that body.encrypted_key is a string.
    const encryptedKey = body.encrypted_key;
    if (typeof encryptedKey !== 'string') {
        throw new ResponseNonSpecCompliant('encrypted_pgp_private_key.encrypted_key was not a string');
    }

    // Assert that body.strategy is a object.
    const strategy = body.strategy;
    if (typeof strategy !== 'object') {
        throw new ResponseNonSpecCompliant('encrypted_pgp_private_key.strategy was not an object');
    }

    // Assert that body.strategy.type is either password or prompt.
    const strategyType = strategy.type;
    if (strategyType === 'password') {
        // Do nothing.
    } else if (strategyType === 'prompt') {
        // Assert that body.strategy.sha256 is a boolean.
        const strategySha256 = strategy.sha256;
        if (typeof strategySha256 !== 'boolean') {
            throw new ResponseNonSpecCompliant('encrypted_pgp_private_key.strategy.sha256 was not a boolean');
        }
    } else {
        // Invalid type.
        throw new ResponseNonSpecCompliant('encrypted_pgp_private_key.strategy.type was not password or prompt');
    }

    // Return the body.
    return body;
};

const decrypt = async (message: string, privateKey: PrivateKey) => {
    const openpgp = await openpgpImport;
    const res = await openpgp.decrypt({
        message: await openpgp.readMessage({
            armoredMessage: message,
        }),
        decryptionKeys: [privateKey],
        format: 'utf8',
    }).then((x: any) => x.data) as string;
    return res;
};

const decryptBytes = async (message: string, privateKey: PrivateKey) => {
    const openpgp = await openpgpImport;
    const res = await openpgp.decrypt({
        message: await openpgp.readMessage({
            armoredMessage: message,
        }),
        decryptionKeys: [privateKey],
        format: 'binary',
    }).then((x: any) => x.data) as Uint8Array;
    return res;
};

const encrypt = async (message: string, publicKey: PublicKey): Promise<string> => {
    const openpgp = await openpgpImport;
    const res = await openpgp.encrypt({
        message: await openpgp.createMessage({
            text: message,
        }),
        encryptionKeys: [publicKey],
        format: 'armored',
    }) as string;
    return res;
};

const mustArray = (name: string, value: any): any[] => {
    if (!Array.isArray(value)) {
        throw new ResponseNonSpecCompliant(`${name} was not an array`);
    }
    return value;
};

const mustString = (name: string, value: any): string => {
    if (typeof value !== 'string') {
        throw new ResponseNonSpecCompliant(`${name} was not a string`);
    }
    return value;
};

const mustNumber = (name: string, value: any): number => {
    if (typeof value !== 'number') {
        throw new ResponseNonSpecCompliant(`${name} was not a number`);
    }
    return value;
};

const mustBoolean = (name: string, value: any): boolean => {
    if (typeof value !== 'boolean') {
        throw new ResponseNonSpecCompliant(`${name} was not a boolean`);
    }
    return value;
};

const encodeEmail = (headers: {[key: string]: string}, body: ArrayBuffer): string => {
    // Encode the headers.
    let out = '';
    for (const key in headers) {
        out += `${key}: ${headers[key]}\r\n`;
    }

    // Add the body.
    out += '\r\n';
    const bodyString = new TextDecoder('utf-8').decode(body);
    out += bodyString;

    // Return the encoded email.
    return out;
};

const justEmail = (toHeader: string): string | null => {
    // Handle all the intricacies of RFC 5322 email addresses and just
    // return the email address.
    const match = toHeader.match(/<([^>]+)>/);
    if (match) {
        return match[1];
    }
    return null;
};

type UnencryptedEmailData = {
    publicKeyUsedHash: string;
    domainVerified: boolean;
    emailId: string | number;
    inboxId: string | number;
    timestamp: number;
};

export type Email = UnencryptedEmailData & ({
    decryptedSuccessfully: false;
} | {
    decryptedSuccessfully: true;
    domain: string;
    from: string;
    subject: string;
    remainder: ArrayBuffer;
});

export class UserClient {
    // Get the password as both a base64 encoded sha-512 hash (used for basic auth) and
    // a sha-256 hash (used for encrypting the private key with the password strategy).
    private sha512B64PasswordPromise: Promise<string>;
    private sha256PasswordPromise: Promise<ArrayBuffer>;

    // Defines the token storage. When this is present, it will try and get the token from
    // here before doing basic authentication and will update the token here when it gets
    // a new one.
    private tokenStorage?: TokenStorage;

    // Setup all the variables and hashes.
    constructor(public url: string, public email: string, password: string) {
        // Make sure the URL is valid.
        new URL(url);

        // Get a base64 sha-512 hash of the password.
        this.sha512B64PasswordPromise = crypto.subtle.digest(
            'SHA-512', new TextEncoder().encode(password),
        ).then(
            x => {
                return new TextDecoder('utf-8').decode(x);
            },
        );

        // Get a sha-256 hash of the password.
        this.sha256PasswordPromise = crypto.subtle.digest(
            'SHA-256', new TextEncoder().encode(password),
        );
    }

    // Sets the token storage object which is used for requests to the server.
    setTokenStorage(tokenStorage: TokenStorage) {
        this.tokenStorage = tokenStorage;
    }

    // Handles making a request to the CEMTP server.
    private async makeRequest(type: string, data: any): Promise<any> {
        // Defines the body and headers.
        const body = JSON.stringify({t: type, d: data});
        const headers: {[key: string]: string} = {
            'X-Cemtp-Supported-Specifications': 'cemtp1.0',
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': `${body.length}`,
            Accept: 'application/json',
        };

        // If the token storage is present, get the token and add it to the headers.
        let token: string | null = null;
        const s = this.tokenStorage;
        if (s) {
            token = await s.get();
        }

        // Handle the authorization header.
        if (token) {
            headers.Authorization = `Bearer ${token}`;
        } else {
            const password = await this.sha512B64PasswordPromise;
            headers.Authorization = `Basic ${btoa(`${this.email}:${password}`)}`;
        }

        // Make the request.
        const response = await fetch(this.url, {
            method: 'POST',
            headers,
            body,
        });

        // If this is a token request, look out for X-New-Token and update the token storage.
        if (s) {
            const newToken = response.headers.get('X-New-Token');
            if (newToken) {
                await s.set(newToken);
            }
        }

        // If the response is not ok, throw an error.
        if (!response.ok) {
            await handleError(response, token === null);
        }

        // Check if X-Cemtp-Version is 1.0. If not, throw a ResponseNonSpecCompliant error.
        const version = response.headers.get('X-Cemtp-Version');
        if (version !== '1.0') {
            throw new ResponseNonSpecCompliant('X-Cemtp-Version was not 1.0, only 1.0 is supported');
        }

        // Return the response.
        return response.status === 204 ? null : response.json();
    }

    // Defines the get pgp key endpoint handler.
    async getPgpKey(email: string) {
        const r = await this.makeRequest('GET_PGP_KEY', email);
        return mustString('Response', r);
    }

    // Defines the send email endpoint handler.
    async sendEmail(opts: SendEmailUserOptions) {
        const body: {[key: string]: any} = {
            encrypted: opts.encrypted,
        };
        if (opts.encrypted) {
            // Load the PGP public key.
            const openpgp = await openpgpImport;
            const publicKey = await openpgp.readKey({
                armoredKey: opts.publicKey,
            });

            // Encrypt the split out headers.
            const headers = {...opts.otherHeaders};
            headers.To = opts.to;
            const toCut = justEmail(opts.to);
            if (!toCut) throw new Error('To header was not a valid email address');
            body.to = toCut;
            body.encrypted_subject = await encrypt(opts.subject, publicKey);
            body.from = opts.from; // 6.2. "Note that for the encrypted body, when sent via a authenticated user, encrypted_from should be changed to from and sent un-encrypted to the server. This is to prevent forgery incidents."
            body.encrypted_remainder = await encrypt(encodeEmail(headers, opts.body), publicKey);
        } else {
            // Make sure From and To are present.
            if (!opts.headers.From) {
                throw new ResponseNonSpecCompliant('Headers.From was not present');
            }
            if (!opts.headers.To) {
                throw new ResponseNonSpecCompliant('Headers.To was not present');
            }

            // Encode the contents.
            body.body = encodeEmail(opts.headers, opts.body);
        }

        // Make the request.
        await this.makeRequest('SEND_EMAIL', body);
    }

    // Defines the me endpoint handler.
    async me(options?: MeOptions) {
        // Make sure the options are present.
        if (!options) options = {};

        // If the cacher is present, try and get the me response from it.
        const cacher = options.cacher;
        if (cacher) {
            const cached = await cacher.get();
            if (cached) return cached;
        }

        // Get the prompt handler.
        const promptHn = options.prompt || defaultPromptHn;

        // Make the ME request.
        const meResponse = await this.makeRequest('ME', null);

        // Make sure it is a object.
        if (typeof meResponse !== 'object') {
            throw new ResponseNonSpecCompliant('ME response was not an object');
        }

        // Get the encrypted PGP key object.
        const encryptedPgpKey = processEncryptedPgpKey(meResponse.encrypted_pgp_private_key);
        let pgpPrivateKey = '';
        if (encryptedPgpKey) {
            // Follow the specified strategy.
            let decryptionKey = await this.sha256PasswordPromise;
            if (encryptedPgpKey.strategy.type === 'prompt') {
                // Get the decryption key with a prompt.
                const d = await promptHn(false);
                if (typeof d === 'string') {
                    // Encode this.
                    decryptionKey = new TextEncoder().encode(d);
                } else {
                    // Easy.
                    decryptionKey = d;
                }

                if (encryptedPgpKey.strategy.sha256) {
                    // Go ahead and sha256 this.
                    decryptionKey = await crypto.subtle.digest('SHA-256', decryptionKey);
                } else if (decryptionKey.byteLength !== 32) {
                    // Make sure it is 32 bytes is the sha256 strategy is off.
                    throw new PromptResponseError('Decryption key was not 32 bytes');
                }
            }

            // Turn the base64 encoded encrypted key into a ArrayBuffer.
            let encryptedKey = await base64ToBufferAsync(encryptedPgpKey.encrypted_key);

            // Get the IV from the first 12 bytes of the encrypted key.
            const iv = encryptedKey.slice(0, 12);
            encryptedKey = encryptedKey.slice(12);

            // Make sure the IV is 12 bytes.
            if (iv.byteLength !== 12) {
                throw new ResponseNonSpecCompliant('IV was not 12 bytes');
            }

            // Decrypt the key.
            const key = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                },
                await crypto.subtle.importKey(
                    'raw', decryptionKey, 'AES-GCM', false, ['decrypt'],
                ),
                encryptedKey,
            );

            // Decode the key.
            pgpPrivateKey = new TextDecoder('utf-8').decode(key);
        } else {
            // Get the PGP private key with a prompt.
            const p = await promptHn(true);
            if (typeof p === 'string') {
                // Easy.
                pgpPrivateKey = p;
            } else {
                // Decode it.
                pgpPrivateKey = new TextDecoder('utf-8').decode(p);
            }
        }

        // Load the PGP private key.
        const openpgp = await openpgpImport;
        const privateKey = await openpgp.readPrivateKey({
            armoredKey: pgpPrivateKey,
        });

        // Decrypt the name.
        const name = await decrypt(mustString('name', meResponse.encrypted_name), privateKey);

        // Get the me response.
        const folders: DecryptedFolder[] = [];
        for (const i in mustArray('folders', meResponse.folders)) {
            const x = meResponse.folders[i];
            const out: DecryptedFolder = {
                folderId: x.folder_id,
                folderName: await decrypt(mustString(`folders[${i}].folder_name`, x.folder_name), privateKey),
                count: mustNumber(`folders[${i}].count`, x.count),
            };
            folders.push(out);
        }
        const out: DecryptedMeResponse = {
            name, emails: mustArray('emails', meResponse.emails).map((x, i) => {
                return mustString(`emails[${i}]`, x);
            }), pgpPrivateKey, folders,
            pgpPublicKey: mustString('pgp_public_key', meResponse.pgp_public_key),
        }

        // If the cacher is present, cache the me response.
        if (cacher) {
            await cacher.set(out);
        }

        // Return the me response.
        return out;
    }

    // Defines an array of additional private keys to use for decryption.
    private additionalPrivateKeys: Promise<PrivateKey>[] = [];

    // Adds a additional private key to use for decryption. This is useful for expired
    // PGP keys that are still used for decryption and sent outside of the CEMTP protocol.
    addAdditionalPrivateKey(privateKey: string) {
        this.additionalPrivateKeys.push(openpgpImport.then(x => x.readPrivateKey({
            armoredKey: privateKey,
        })));
    }

    // Parses a email object.
    private async parseEmail(x: any, privateKeys: PrivateKey[]): Promise<Email> {
        // Make sure the email is a object.
        if (typeof x !== 'object') {
            throw new ResponseNonSpecCompliant('email was not an object');
        }

        // Get the unencrypted email data.
        const unencryptedEmailData: UnencryptedEmailData = {
            publicKeyUsedHash: mustString('emails.public_key_used_hash', x.public_key_used_hash),
            domainVerified: mustBoolean('emails.domain_verified', x.domain_verified),
            emailId: mustString('emails.email_id', x.email_id),
            inboxId: mustString('emails.inbox_id', x.inbox_id),
            timestamp: mustNumber('emails.timestamp', x.timestamp),
        };

        // Attempt to find the private key used.
        let privateKey: PrivateKey | null = null;
        for (const key of privateKeys) {
            const publicKey = key.toPublic().armor();
            const hashedKey = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(publicKey)).then(
                x => new TextDecoder('utf-8').decode(x),
            );
            if (hashedKey === unencryptedEmailData.publicKeyUsedHash) {
                // Found it.
                privateKey = key;
                break;
            }
        }

        // If the private key is null, it means we don't have the private key. Return the email here.
        if (!privateKey) {
            return {
                ...unencryptedEmailData,
                decryptedSuccessfully: false,
            };
        }

        // Decrypt the email.
        return {
            ...unencryptedEmailData,
            decryptedSuccessfully: true,
            domain: await decrypt(mustString('emails.encrypted_domain', x.encrypted_domain), privateKey),
            from: await decrypt(mustString('emails.encrypted_from', x.encrypted_from), privateKey),
            subject: await decrypt(mustString('emails.encrypted_subject', x.encrypted_subject), privateKey),
            remainder: await decryptBytes(mustString('emails.encrypted_remainder', x.encrypted_remainder), privateKey),
        }
    }

    // Defines the get email endpoint handler. This function uses the me endpoint to get
    // the private key so contains the configuration for that too.
    async getEmail(opts: {
        page?: number;
        limit?: number;
        folder_id?: string | number;
        since?: number;
    }, meOptions?: MeOptions): Promise<{
        pagination: {
            limit: number;
            currentPage: number;
            nextPage: boolean;
        };
        emails: Email[];
    }> {
        // Get the private keys.
        const me = await this.me(meOptions);
        const privateKeys: PrivateKey[] = [];
        for (const key of this.additionalPrivateKeys) {
            privateKeys.push(await key);
        }
        privateKeys.push(await openpgpImport.then(x => x.readPrivateKey({
            armoredKey: me.pgpPrivateKey,
        })));

        // Make the request.
        const resp = await this.makeRequest('GET_EMAIL', opts);

        // Make sure it is a object.
        if (typeof resp !== 'object') {
            throw new ResponseNonSpecCompliant('GET_EMAIL response was not an object');
        }

        // Get the pagination.
        const rawPagination = resp.pagination;
        if (typeof rawPagination !== 'object') {
            throw new ResponseNonSpecCompliant('pagination was not an object');
        }

        // Validate the pagination.
        const pagination = {
            limit: mustNumber('pagination.limit', rawPagination.limit),
            currentPage: mustNumber('pagination.current_page', rawPagination.current_page),
            nextPage: mustBoolean('pagination.next_page', rawPagination.next_page),
        };

        // Handle if the emails is not an array.
        const rawEmails = mustArray('emails', resp.emails);
        const emails: Email[] = [];
        for (const i in rawEmails) {
            const x = rawEmails[i];
            emails.push(await this.parseEmail(x, privateKeys));
        }

        // Return the response.
        return { pagination, emails };
    }

    // Defines the delete email endpoint handler.
    async deleteEmail(emailId: string | number) {
        await this.makeRequest('DELETE_EMAIL', emailId);
    }

    // Defines the move emails endpoint handler.
    async moveEmails(emailIds: (string | number)[], folderId: string | number) {
        await this.makeRequest('MOVE_EMAILS', { email_ids: emailIds, folder_id: folderId });
    }
}
