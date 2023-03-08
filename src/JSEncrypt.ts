/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { b64tohex, hex2b64 } from './lib/jsbn/base64';
import { Hex } from './lib/asn1js/hex';
import { Base64 } from './lib/asn1js/base64';
import { ASN1 } from './lib/asn1js/asn1';
import { RSAKey } from './lib/jsbn/rsa';
import { parseBigInt } from './lib/jsbn/jsbn';

const rsaKey = new RSAKey();

export const encrypt = (data: string, publicKey: string): string => {
	parseKey(publicKey);
	return hex2b64(rsaKey.encrypt(data)).toString();
};

export const decrypt = (data: string, privateKey: string) => {
	parseKey(privateKey);
	return rsaKey.decrypt(b64tohex(data))?.toString();
};

function parseKey(pem: string) {
	try {
		let modulus = '0';
		let public_exponent = '0';
		const reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/;
		const der = reHex.test(pem) ? Hex.decode(pem) : Base64.unarmor(pem);
		let asn1 = ASN1.decode(der);
		// Fixes a bug with OpenSSL 1.0+ private keys
		if (asn1.sub.length === 3) {
			asn1 = asn1.sub[2].sub[0];
		}
		if (asn1.sub.length === 9) {
			// Parse the private key.
			modulus = asn1.sub[1].getHexStringValue(); // bigint
			rsaKey.n = parseBigInt(modulus, 16);
			public_exponent = asn1.sub[2].getHexStringValue(); // int
			rsaKey.e = parseInt(public_exponent, 16);
			const private_exponent = asn1.sub[3].getHexStringValue(); // bigint
			rsaKey.d = parseBigInt(private_exponent, 16);
			const prime1 = asn1.sub[4].getHexStringValue(); // bigint
			rsaKey.p = parseBigInt(prime1, 16);
			const prime2 = asn1.sub[5].getHexStringValue(); // bigint
			rsaKey.q = parseBigInt(prime2, 16);
			const exponent1 = asn1.sub[6].getHexStringValue(); // bigint
			rsaKey.dmp1 = parseBigInt(exponent1, 16);
			const exponent2 = asn1.sub[7].getHexStringValue(); // bigint
			rsaKey.dmq1 = parseBigInt(exponent2, 16);
			const coefficient = asn1.sub[8].getHexStringValue(); // bigint
			rsaKey.coeff = parseBigInt(coefficient, 16);
		}
		else if (asn1.sub.length === 2) {
			if (asn1.sub[0].sub) {
				// Parse ASN.1 SubjectPublicKeyInfo type as defined by X.509
				const bit_string = asn1.sub[1];
				const sequence = bit_string.sub[0];
				modulus = sequence.sub[0].getHexStringValue();
				rsaKey.n = parseBigInt(modulus, 16);
				public_exponent = sequence.sub[1].getHexStringValue();
				rsaKey.e = parseInt(public_exponent, 16);
			}
			else {
				// Parse ASN.1 RSAPublicKey type as defined by PKCS #1
				modulus = asn1.sub[0].getHexStringValue();
				rsaKey.n = parseBigInt(modulus, 16);
				public_exponent = asn1.sub[1].getHexStringValue();
				rsaKey.e = parseInt(public_exponent, 16);
			}
		}
		else {
			return false;
		}
		return true;
	}
	catch (ex) {
		return false;
	}

}
