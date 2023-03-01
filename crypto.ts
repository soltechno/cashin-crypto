import CryptoJS from 'crypto-js';

let publicKey: string;
let encryptionKey: string;

export const generatePublicKey = (generatorBase: number, privateKey: number, bigPrime: number) => {
  publicKey = expmod(generatorBase, privateKey, bigPrime).toString();
};

export const generateEncryptionKey = (clientPublicKey: number, privateKey: number, bigPrime: number) => {
  encryptionKey = expmod(clientPublicKey, privateKey, bigPrime).toString();
};

function expmod(base: number, key: number, mod: number) {
  return (Math.pow(base, key)) % mod;
}

export const getPublicKey = (): string => {
  return publicKey;
};

export const getEncryptionKey = (): string => {
  return encryptionKey;
};

export const encryptData = (data: string): string => {
  return CryptoJS.AES.encrypt(data, encryptionKey).toString();
};

export const decryptData = (data: string): string => {
  return CryptoJS.AES.decrypt(data, encryptionKey).toString(CryptoJS.enc.Utf8);
};


