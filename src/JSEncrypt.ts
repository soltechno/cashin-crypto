import { b64tohex, hex2b64 } from './lib/jsbn/base64';
import { JSEncryptRSAKey } from './JSEncryptRSAKey';

export const encrypt = (data: string, publicKey: string): string => {
	const rsaKey = new JSEncryptRSAKey(publicKey);
	return hex2b64(rsaKey.encrypt(data)).toString();
};

export const decrypt = (data: string, privateKey: string) => {
	const rsaKey = new JSEncryptRSAKey(privateKey);
	return rsaKey.decrypt(b64tohex(data))?.toString();
};
