import { Buffer } from "buffer";
import * as asn1js from "asn1js";
import { Poseidon } from "@iden3/js-crypto";
import { HashAlgorithm } from "./helpers/HashAlgorithm";
import { Sod } from "./utils";
import { DG1, DG15, SOD } from "@li0ard/tsemrtd";
import { CertificateSet } from "@peculiar/asn1-cms";
import { ProposalData } from "./types";

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
  NotRegistered = "NOT_REGISTERED",
  RegisteredWithThisPk = "REGISTERED_WITH_THIS_PK",
  RegisteredWithOtherPk = "REGISTERED_WITH_OTHER_PK",
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
    if (this.dataGroup15) {
      const key = this.parseDg15Pubkey();

      if (key.type === "Ecdsa") {
        return RarimePassport.extractEcdsaPassportKey(key.keyBytes);
      } else {
        return RarimePassport.extractRsaPassportKey(key.modulus, key.exponent);
      }
    }

    return this.getPassportHash();
  }

  public getPassportHash(): bigint {
    const signedAttributes = this.extractSignedAttributes();

    let hashBlock = HashAlgorithm.fromOID(this.getSignatureAlgorithm());

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

  private parseDg15Pubkey(): ActiveAuthKey {
    if (!this.dataGroup15) {
      throw new Error("DG15 data is not provided");
    }

    // DG15 contains SubjectPublicKeyInfo (SPKI)
    const spki = DG15.load(Buffer.from(this.dataGroup15));
    const algorithmOid = spki.algorithm.algorithm; // OID string

    // BIT STRING in SPKI: first octet is 'unused bits' count (usually 0)
    let spkBytes = new Uint8Array(spki.subjectPublicKey);
    if (spkBytes.length > 0 && spkBytes[0] === 0x00) {
      spkBytes = spkBytes.slice(1);
    }

    // RSA public key
    if (algorithmOid === "1.2.840.113549.1.1.1") {
      const der = spkBytes.buffer.slice(
        spkBytes.byteOffset,
        spkBytes.byteOffset + spkBytes.byteLength
      );
      const asn = asn1js.fromBER(der);
      if (asn.offset === -1 || !(asn.result instanceof asn1js.Sequence)) {
        throw new Error("Failed to parse RSA public key from DG15");
      }

      const seq = asn.result as asn1js.Sequence;
      const values = (seq.valueBlock as any).value as any[];
      if (!values || values.length < 2) {
        throw new Error("Invalid RSA public key structure");
      }

      const modulusBlock = values[0] as asn1js.Integer;
      const exponentBlock = values[1] as asn1js.Integer;

      const modBuf = Buffer.from(
        (modulusBlock.valueBlock as any).valueHex as ArrayBuffer
      );
      const expBuf = Buffer.from(
        (exponentBlock.valueBlock as any).valueHex as ArrayBuffer
      );

      const modulus = BigInt("0x" + modBuf.toString("hex"));
      const exponent = BigInt("0x" + expBuf.toString("hex"));

      return { type: "Rsa", modulus, exponent };
    }

    // EC public key (uncompressed EC point)
    if (algorithmOid === "1.2.840.10045.2.1") {
      return { type: "Ecdsa", keyBytes: spkBytes };
    }

    throw new Error(`Unsupported public key algorithm OID: ${algorithmOid}`);
  }

  validate(proposalData: ProposalData) {
    console.log("passport");
    const mrz = this.getMRZData();
    console.log("mrz", mrz);
    if (
      proposalData.criteria.citizenshipWhitelist.length &&
      !proposalData.criteria.citizenshipWhitelist.includes(
        BigInt("0x" + Buffer.from(mrz.issuingCountry).toString("hex"))
      )
    ) {
      throw new Error("Citizen is not in whitelis");
    }
    console.log("contract");
    if (
      proposalData.criteria.sex !== 0n &&
      proposalData.criteria.sex === BigInt(mrz.sex)
    ) {
      throw new Error("Sex mismatch");
    }
    console.log("sex");
    if (
      proposalData.criteria.birthDateLowerbound != 52983525027888n &&
      proposalData.criteria.birthDateLowerbound > BigInt(mrz.birthDate)
    ) {
      throw new Error("Birth date is lover then lowerbound");
    }
    console.log("BiD lover");
    if (
      proposalData.criteria.birthDateUpperbound != 52983525027888n &&
      proposalData.criteria.birthDateUpperbound < BigInt(mrz.birthDate)
    ) {
      throw new Error("Birth date is higher then upperbound");
    }
    console.log("BiD lover");
    if (
      proposalData.criteria.expirationDateLowerbound != 52983525027888n &&
      proposalData.criteria.expirationDateLowerbound > BigInt("0x" + Buffer.from(mrz.expiryDate).toString("hex"))
    ) {
      console.log(
        "proposalData.criteria.expirationDateLowerbound",
        proposalData.criteria.expirationDateLowerbound
      );
      console.log("BigInt(mrz.expiryDate)", BigInt(mrz.expiryDate));
      throw new Error("Expiration date is lover then lowerbound");
    }
    console.log("Expiration lover");
  }

  public getMRZData(): MRZData {
    const mrz = DG1.load(this.dataGroup1);

    const documentType = mrz.slice(0, 2);
    const issuingCountry = mrz.slice(2, 5);
    const documentNumber = mrz.slice(5, 14);

    const birthDate = mrz.slice(30, 36);

    const sexChar = mrz.charAt(37);

    const sex = sexChar;

    const expiryDate = mrz.slice(38, 44);

    const namesPart = mrz.slice(60);
    // split by '<<' like in Rust .split("<<")
    const names = namesPart.split("<<");
    const lastNameRaw = names[0] ?? "";
    const firstNameRaw = names[1] ?? "";

    const result: MRZData = {
      documentType,
      issuingCountry,
      documentNumber,
      birthDate,
      sex,
      expiryDate,
      lastName: lastNameRaw,
      firstName: firstNameRaw,
    };
    return result;
  }
}
