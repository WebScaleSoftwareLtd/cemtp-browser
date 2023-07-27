// JS implementation of a Client-side Encrypted Mail Transfer Protocol (CEMTP) user client.
// Copyright (C) 2023 Web Scale Software Ltd. Licensed under the MIT license.
// Written By: Astrid Gealer <astrid@webscalesoftware.ltd>

import { openpgpImport, base64ToBufferAsync } from "./shared";

const arrayBufferToBase64 = (buffer: ArrayBuffer): Promise<string> => new Promise(res => {
    const blob = new Blob([buffer]);
    const reader = new FileReader();

    reader.onload = (event) => {
        const dataUrl = event.target!.result!;
        const [_, base64] = (dataUrl as string).split(',');
        res(base64);
    };

    reader.readAsDataURL(blob);
});

// Encrypts a message using the password.
const encryptMessage = async (message: string, password: string): Promise<string> => {
    // Hash the password to SHA-256.
    const passwordHash = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(password),
    );

    // Generate a IV.
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the message with AES-GCM.
    const res = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
        },
        await crypto.subtle.importKey(
            'raw', passwordHash, 'AES-GCM', false, ['encrypt', 'decrypt'],
        ),
        new TextEncoder().encode(message),
    );

    // Stick the IV at the start.
    const resWithIV = new Uint8Array(iv.length + res.byteLength);
    resWithIV.set(iv);
    resWithIV.set(new Uint8Array(res), iv.length);

    // Base64 encode the encrypted message.
    return arrayBufferToBase64(resWithIV.buffer);
};

// Generates a public PGP key and a encrypted private PGP key string from a password using
// the password strategy.
export const generateKeyPair = async (email: string, password: string): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
}> => {
    // Load openpgp.
    const openpgp = await openpgpImport;

    // Generate the key pair.
    const keyPair = await openpgp.generateKey({
        rsaBits: 4096,
        format: 'armored',
        userIDs: [
            {
                email,
            },
        ],
    });

    // Return the public key and the encrypted private key.
    return {
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: await encryptMessage(keyPair.privateKey, password),
    };
};

// Re-encrypts a private PGP key string with a new password.
export const reencryptPrivateKey = async (privateKey: string, oldPassword: string, newPassword: string): Promise<string> => {
    // Get the private key as a buffer.
    let privateKeyBuffer = await base64ToBufferAsync(privateKey);

    // Get the IV from the first 12 bytes of the encrypted key.
    const iv = privateKeyBuffer.slice(0, 12);
    privateKeyBuffer = privateKeyBuffer.slice(12);

    // Make sure the IV is 12 bytes.
    if (iv.byteLength !== 12) {
        throw new Error('IV was not 12 bytes');
    }

    // Hash the old password to SHA-256.
    const oldPasswordHash = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(oldPassword),
    );

    // Decrypt the private key with AES-GCM.
    const decryptedPrivateKey = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv,
        },
        await crypto.subtle.importKey(
            'raw', oldPasswordHash, 'AES-GCM', false, ['encrypt', 'decrypt'],
        ),
        privateKeyBuffer,
    );

    // Encode the decrypted private key as a string.
    const decryptedPrivateKeyString = new TextDecoder().decode(decryptedPrivateKey);

    // Return the encrypted private key.
    return encryptMessage(decryptedPrivateKeyString, newPassword);
};
