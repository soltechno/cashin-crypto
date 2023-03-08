import { BigInteger } from "./jsbn";
export declare class RSAKey {
    constructor();
    doPublic(x: BigInteger): BigInteger;
    doPrivate(x: BigInteger): BigInteger;
    encrypt(text: string): string;
    decrypt(ctext: string): string;
    n: BigInteger;
    e: number;
    d: BigInteger;
    p: BigInteger;
    q: BigInteger;
    dmp1: BigInteger;
    dmq1: BigInteger;
    coeff: BigInteger;
}
