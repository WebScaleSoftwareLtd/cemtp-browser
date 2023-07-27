// Async import openpgp since it's a large library.
export const openpgpImport = import('openpgp').then(x => x.default);

// From: https://stackoverflow.com/a/54123275 (with some modifications)
export function base64ToBufferAsync(base64: string) {
    const dataUrl = 'data:application/octet-binary;base64,' + base64;

    return fetch(dataUrl).then(res => res.arrayBuffer());
}
