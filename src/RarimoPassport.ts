import {Buffer} from "buffer";
import * as asn1js from "asn1js";
import {StateKeeper} from "./types/contracts";
import {Poseidon} from "@iden3/js-crypto";
import {HashAlgorithm} from "./helpers/HashAlgorithm";
import {Sod} from "./utils";
import {SOD} from "@li0ard/tsemrtd";
import {CertificateSet} from "@peculiar/asn1-cms";

export type PassportInfo = {
    passportInfo_: StateKeeper.PassportInfoStructOutput;
    identityInfo_: StateKeeper.IdentityInfoStructOutput;
};

export interface MRZData {
    documentType: string;
    issuingCountry: string;
    documentNumber: string;
    birthDate: string;
    sex: string;
    expiryDate: string;
    lastName: string;
    firstName: string;
}

export type ActiveAuthKey =
    | { type: "Rsa"; modulus: bigint; exponent: bigint }
    | { type: "Ecdsa"; keyBytes: Uint8Array };

export enum DocumentStatus {
    NotRegistered,
    RegisteredWithThisPk,
    RegisteredWithOtherPk,
}

export interface RarimePassportProps {
    dataGroup1: Uint8Array;
    sod: Uint8Array;
    dataGroup15?: Uint8Array;
    aaSignature?: Uint8Array;
    aaChallenge?: Uint8Array;
}

export interface VotingCriteria {
    citizenshipWhitelist: string[];
    sex: string;
    birthDateLowerbound: string;
    birthDateUpperbound: string;
    expirationDateLowerbound: string;
}

export class RarimePassport {
    public dataGroup1: Uint8Array;
    public dataGroup15?: Uint8Array;
    public aaSignature?: Uint8Array;
    public aaChallenge?: Uint8Array;
    public sod: Uint8Array;

    constructor(props: RarimePassportProps) {
        this.dataGroup1 = props.dataGroup1;
        this.sod = props.sod;
        this.dataGroup15 = props.dataGroup15;
        this.aaSignature = props.aaSignature;
        this.aaChallenge = props.aaChallenge;
    }

    private static extractEcdsaPassportKey(keyBytes: Uint8Array): bigint {
        if (keyBytes.length !== 65 || keyBytes[0] !== 0x04) {
            throw new Error("UnsupportedPassportKey: Invalid ECDSA key format");
        }

        const xBytes = keyBytes.slice(1, 33);
        const yBytes = keyBytes.slice(33, 65);

        const xHex = Array.from(xBytes, (b) =>
            b.toString(16).padStart(2, "0")
        ).join("");
        const yHex = Array.from(yBytes, (b) =>
            b.toString(16).padStart(2, "0")
        ).join("");

        const x = BigInt("0x" + xHex);
        const y = BigInt("0x" + yHex);

        // 2^248
        const modulus = 1n << 248n;

        const xMod = x % modulus;
        const yMod = y % modulus;

        return Poseidon.hash([xMod, yMod]);
    }

    private static extractRsaPassportKey(
        modulus: bigint,
        exponent: bigint
    ): bigint {
        const bitLen = modulus.toString(2).length;
        const requiredBits = 200 * 4 + 224; // 1024

        if (bitLen < requiredBits) {
            throw new Error("UnsupportedPassportKey: Modulus too short");
        }

        const shift = BigInt(bitLen - requiredBits);
        let topBits = modulus >> shift;

        const chunkSizes = [224, 200, 200, 200, 200];
        const chunks: bigint[] = [];

        for (const size of chunkSizes) {
            const mask = (1n << BigInt(size)) - 1n;
            const chunk = topBits & mask;
            chunks.push(chunk);

            topBits >>= BigInt(size);
        }

        chunks.reverse();

        return Poseidon.hash(chunks);
    }

    public getPassportKey(): bigint {
        console.log("get pass key", this);
        if (this.dataGroup15) {
            console.log("has dg15");
            const key = this.parseDg15Pubkey(this.dataGroup15);

            if (key.type === "Ecdsa") {
                return RarimePassport.extractEcdsaPassportKey(key.keyBytes);
            } else {
                return RarimePassport.extractRsaPassportKey(key.modulus, key.exponent);
            }
        }
        console.log("no dg15");
        return this.getPassportHash();
    }

    public getPassportHash(): bigint {
        const signedAttributes = this.extractSignedAttributes();
        console.log("signed attr", signedAttributes);
        let hashBlock = HashAlgorithm.fromOID(this.getSignatureAlgorithm());
        console.log("hash block", hashBlock);
        let hashBytes = hashBlock.getHashFixed32(signedAttributes);

        let out = 0n;
        let acc = 0n;
        let accBits = 0;

        for (let i = 251; i >= 0; i--) {
            const byteIndex = Math.floor(i / 8);
            const bitIndex = 7 - (i % 8);
            const bit = (BigInt(hashBytes[byteIndex]) >> BigInt(bitIndex)) & 1n;

            // acc = (acc << 1) | bit
            acc = (acc << 1n) | bit;
            accBits += 1;

            if (accBits === 64) {
                out = (out << 64n) | acc;
                acc = 0n;
                accBits = 0;
            }
        }

        if (accBits > 0) {
            out = (out << BigInt(accBits)) | acc;
        }

        return Poseidon.hash([out]);
    }

    public extractSignedAttributes(): Uint8Array {
        const buffer = this.sod;
        const sod = new Sod(buffer);
        const signedAttributes = sod.signedAttributes;
        return signedAttributes;
    }

    public extractDGHashAlgo(): string {
        const buffer = Buffer.from(this.sod); // Use tsmrtd's SOD parser
        const sod = SOD.load(buffer);
        return sod.ldsObject.algorithm.algorithm;
    }

    public getDgHashAlgorithm(): string {
        const buffer = this.sod;

        const asn1Result = asn1js.fromBER(buffer);

        if (asn1Result.offset === -1) {
            throw new Error("ASN1DecodeError: Failed to decode BER data");
        }

        const blocks = [asn1Result.result];

        const app23Block = blocks.find(
            (block) => block.idBlock.tagClass === 2 && block.idBlock.tagNumber === 23
        );

        if (!app23Block) {
            throw new Error("Expected Application 23 SEQUENCE in the root");
        }

        const seqInApp23 = (app23Block.valueBlock as any)
            .value as asn1js.BaseBlock[];

        if (!Array.isArray(seqInApp23)) {
            throw new Error("Expected SEQUENCE inside Application 23");
        }

        const tagged0Block = seqInApp23.find(
            (block) => block.idBlock.tagClass === 3 && block.idBlock.tagNumber === 0
        );

        if (!tagged0Block) {
            throw new Error("No [0] tagged block found");
        }

        const seqInTagged0 = (tagged0Block.valueBlock as any)
            .value as asn1js.BaseBlock[];

        if (!Array.isArray(seqInTagged0)) {
            throw new Error("Expected SEQUENCE inside [0]");
        }

        const setBlock = seqInTagged0.find(
            (block) => block.idBlock.tagClass === 1 && block.idBlock.tagNumber === 17
        );

        if (!setBlock) {
            throw new Error("No SET found inside [0] SEQUENCE");
        }

        const setContent = (setBlock.valueBlock as any).value as asn1js.BaseBlock[];
        if (!setContent || setContent.length === 0) {
            throw new Error("SET is empty");
        }

        const innerSeq = setContent[0];

        if (innerSeq.idBlock.tagNumber !== 16) {
            throw new Error("Expected SEQUENCE as first element of SET");
        }

        const innerSeqContent = (innerSeq.valueBlock as any)
            .value as asn1js.BaseBlock[];

        if (!innerSeqContent || innerSeqContent.length === 0) {
            throw new Error("Inner SEQUENCE is empty");
        }

        const oidBlock = innerSeqContent[0];

        if (oidBlock.idBlock.tagNumber !== 6) {
            throw new Error(
                "Expected ObjectIdentifier as first element of inner SEQUENCE"
            );
        }

        const oidValue = (
            oidBlock as asn1js.ObjectIdentifier
        ).valueBlock.toString();

        return oidValue;
    }

    public getSignatureAlgorithm(): string {
        const buffer = Buffer.from(this.sod);
        const sod = SOD.load(buffer);

        const signatureAlgorithmOID =
            sod.signatures[0].signatureAlgorithm.algorithm;
        console.log(signatureAlgorithmOID);
        if (!signatureAlgorithmOID.startsWith("1.2.840.")) {
            throw new Error("Signature algorithm OID does not start with 1.2.840.");
        }

        return signatureAlgorithmOID;
    }

    public extractEncapsulatedContent(): Uint8Array {
        const buffer = this.sod;
        const sod = new Sod(buffer);
        const encapsulatedContent = sod.encapsulatedContent;
        return encapsulatedContent;
    }

    public extractSignature(): Uint8Array {
        const buffer = this.sod;
        const sod = new Sod(buffer);
        const signature = sod.signature;
        return signature;
    }

    getCertificate(): CertificateSet {
        const buffer = Buffer.from(this.sod);
        const sod = SOD.load(buffer);
        const certificates = sod.certificates;
        return certificates;
    }

    private parseDg15Pubkey(dg15Bytes: Uint8Array): ActiveAuthKey {
        const asn1 = asn1js.fromBER(Buffer.from(dg15Bytes));
        if (asn1.offset === -1) throw new Error("Decoding DG15 error");

        // Logic roughly matching Rust's traversal:
        // Expected: Application 15 OR Sequence
        // Inside: Sequence -> [AlgorithmIdentifier, BitString]

        let root = asn1.result;

        // Handle explicit Application 15 wrapper if present
        if (root.idBlock.tagClass === 2 && root.idBlock.tagNumber === 15) {
            // Application 15
            // @ts-ignore
            if (!root.valueBlock.value || root.valueBlock.value.length === 0)
                throw new Error("Empty App15");
            // @ts-ignore
            root = root.valueBlock.value[0]; // inner sequence
        }

        // @ts-ignore
        const seq = root.valueBlock.value;
        if (!seq || seq.length < 2) throw new Error("Invalid DG15 structure");

        const bitStringBlock = seq[1]; // subjectPublicKey
        // @ts-ignore
        const keyBytesBuf = bitStringBlock.valueBlock.valueHex;
        const keyBytes = new Uint8Array(keyBytesBuf);

        // Try to parse inner RSA structure
        const innerAsn = asn1js.fromBER(keyBytesBuf);
        if (
            innerAsn.offset !== -1 &&
            innerAsn.result.constructor.name === "Sequence"
        ) {
            // It is likely RSA
            // @ts-ignore
            const rsaInner = innerAsn.result.valueBlock.value;
            if (rsaInner && rsaInner.length >= 2) {
                // @ts-ignore
                const modHex = pvutils.bufferToHexCodes(
                    rsaInner[0].valueBlock.valueHex
                );
                // @ts-ignore
                const expHex = pvutils.bufferToHexCodes(
                    rsaInner[1].valueBlock.valueHex
                );

                return {
                    type: "Rsa",
                    modulus: BigInt(`0x${modHex}`),
                    exponent: BigInt(`0x${expHex}`),
                };
            }
        }

        // Default to ECDSA
        return {
            type: "Ecdsa",
            keyBytes: keyBytes,
        };
    }
}
