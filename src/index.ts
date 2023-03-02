import JSEncrypt from 'jsencrypt';

export const encryptData = (publicKey: string, data: string): string => {
    const crypt = new JSEncrypt();
    crypt.setKey(publicKey);
    return crypt.encrypt(data).toString();
};

export const decryptData = (privateKey: string, data: string): string => {
    const crypt = new JSEncrypt();
    crypt.setKey(privateKey);
    return crypt.decrypt(data).toString();
};


