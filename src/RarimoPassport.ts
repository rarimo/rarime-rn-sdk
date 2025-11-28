import { Buffer } from "buffer";
import * as asn1js from "asn1js";
import { StateKeeper } from "./types/contracts";
import { Poseidon } from "@iden3/js-crypto";
import { ObjectIdentifier } from "asn1js";
import { HashAlgorithm } from "./helpers/HashAlgorithm";

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

  public getPassportKey(): bigint {
    if (this.dataGroup15) {
      const key = this.parseDg15Pubkey(this.dataGroup15);

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

  public extractSignedAttributes(): Uint8Array {
    const buffer = this.sod;

    const asn1Result = asn1js.fromBER(buffer);
    if (asn1Result.offset === -1) {
      throw new Error("ASN1DecodeError: Failed to decode BER data");
    }

    const rootBlock = asn1Result.result;

    if (
      !(rootBlock.idBlock.tagClass === 2 && rootBlock.idBlock.tagNumber === 23)
    ) {
      throw new Error("Expected Application 23 at root");
    }

    const app23SeqContent = (rootBlock.valueBlock as any)
      .value as asn1js.BaseBlock[];

    if (!Array.isArray(app23SeqContent)) {
      throw new Error("Expected SEQUENCE inside Application 23");
    }

    const tagged0Block = app23SeqContent.find(
      (block) => block.idBlock.tagClass === 3 && block.idBlock.tagNumber === 0
    );

    if (!tagged0Block) {
      throw new Error("No [0] tagged block found in Application 23 SEQUENCE");
    }

    const tagged0InnerBlocks: asn1js.BaseBlock[] = (
      tagged0Block.valueBlock as any
    ).value as asn1js.BaseBlock[];

    if (!Array.isArray(tagged0InnerBlocks)) {
      if (tagged0Block.valueBlock instanceof asn1js.ValueBlock) {
        throw new Error("Content inside [0] is not a SEQUENCE/SET.");
      }

      throw new Error("Expected Constructed block inside [0].");
    }

    const finalSeqBlock = tagged0InnerBlocks.find((block) => {
      if (block.idBlock.tagClass === 1 && block.idBlock.tagNumber === 17) {
        const setContent = (block.valueBlock as any)
          .value as asn1js.BaseBlock[];
        if (setContent && setContent.length > 0) {
          const firstElement = setContent[0];
          if (firstElement.idBlock.tagNumber === 16) {
            const seqInner = (firstElement.valueBlock as any)
              .value as asn1js.BaseBlock[];

            if (seqInner && seqInner.length === 6) {
              return true;
            }
          }
        }
      }
      return false;
    });

    if (!finalSeqBlock) {
      throw new Error(
        "No inner SET containing 6-element SEQUENCE found (SignedData structure missing)."
      );
    }

    const finalSeqContent = (
      (finalSeqBlock.valueBlock as any).value as asn1js.BaseBlock[]
    ).find((b) => b.idBlock.tagNumber === 16);

    if (!finalSeqContent) {
      throw new Error(
        "Internal error: Could not find the 6-element SEQUENCE content."
      );
    }

    const signedDataElements = (finalSeqContent.valueBlock as any)
      .value as asn1js.BaseBlock[];

    const signedAttrsBlock = signedDataElements.find(
      (elem) => elem.idBlock.tagClass === 3 && elem.idBlock.tagNumber === 0
    );

    if (!signedAttrsBlock) {
      throw new Error(
        "No [0] tag (SignedAttributes) found inside final SEQUENCE."
      );
    }

    const innerSetBlock = (
      (signedAttrsBlock.valueBlock as any).value as asn1js.BaseBlock[]
    )[0];

    if (!innerSetBlock || innerSetBlock.idBlock.tagNumber !== 17) {
      throw new Error("Expected SET inside SignedAttributes [0] tag.");
    }

    const signedAttributesDer = innerSetBlock.toBER();

    let signedAttributesBytes = new Uint8Array(signedAttributesDer);

    if (signedAttributesBytes.length > 0) {
      signedAttributesBytes[0] = 0x31;
    } else {
      throw new Error("Failed to encode Signed Attributes to DER.");
    }

    return signedAttributesBytes;
  }

  public getMrzString(): string {
    const asn1 = asn1js.fromBER(Buffer.from(this.dataGroup1));
    if (asn1.offset === -1) throw new Error("DG1 decode error");

    const root = asn1.result;
    // @ts-ignore
    const app31 = root.valueBlock.value[0];

    // @ts-ignore
    const content = app31.valueBlock.value[0];

    // @ts-ignore
    const rawBytes = content.valueBlock.valueHex;
    const str = Buffer.from(rawBytes).toString("utf8");

    return str.replace(/\0/g, "");
  }

  public getMrzData(): MRZData {
    const mrzString = this.getMrzString();
    return this.parseMrzTd1String(mrzString);
  }

  private parseMrzTd1String(mrz: string): MRZData {
    // Rust slicing logic 1-to-1
    const namesPart = mrz.substring(60);
    const names = namesPart.split("<<");

    return {
      documentType: mrz.substring(0, 2),
      issuingCountry: mrz.substring(2, 5),
      documentNumber: mrz.substring(5, 14),
      birthDate: mrz.substring(30, 36),
      sex: mrz.charAt(37),
      expiryDate: mrz.substring(38, 44),
      lastName: names[0] || "",
      firstName: names[1] || "",
    };
  }

  public validate(criteria: VotingCriteria): void {
    const mrz = this.getMrzData();

    // Check Whitelist
    if (criteria.citizenshipWhitelist.length > 0) {
      const countryInt = Buffer.from(mrz.issuingCountry, "utf8");
      if (!criteria.citizenshipWhitelist.includes(countryInt.toString())) {
        throw new Error("Citizen is not in whitelist");
      }
    }

    // Sex check
    if (criteria.sex !== "0" && mrz.sex !== criteria.sex) {
      throw new Error("Sex mismatch");
    }

    // const mrzBirth = Buffer.from(mrz.birthDate, "utf8");
    // const mrzExpiry = Buffer.from(mrz.expiryDate, "utf8");

    throw new Error("Method validate not implemented.");
  }

  public extractSignatureOID(): ObjectIdentifier {
    const { result, offset } = asn1js.fromBER(Buffer.from(this.sod));

    if (offset === -1) {
      throw new Error("Failed to decode ASN.1 data");
    }

    const blocks = [result];

    const app23Block = blocks.find(
      (b) => b.idBlock.tagClass === 2 && b.idBlock.tagNumber === 23
    );

    if (!app23Block) {
      throw new Error("Expected Application 23 SEQUENCE in the root");
    }

    const seqInApp23 = (app23Block as asn1js.Constructed).valueBlock.value;
    if (!Array.isArray(seqInApp23)) {
      throw new Error("Expected SEQUENCE inside Application 23");
    }

    const tagged0Block = seqInApp23.find(
      (b) => b.idBlock.tagClass === 3 && b.idBlock.tagNumber === 0
    );

    if (!tagged0Block) {
      throw new Error("No [0] tagged block found");
    }

    const seqInTagged0Content = (tagged0Block as asn1js.Constructed).valueBlock
      .value;

    // Explicit tags usually wrap the content, so we take the first element
    const seqInTagged0Wrapper = seqInTagged0Content[0];

    if (!seqInTagged0Wrapper || seqInTagged0Wrapper.idBlock.tagNumber !== 16) {
      throw new Error("Expected SEQUENCE inside [0]");
    }

    const seqInTagged0 = (seqInTagged0Wrapper as asn1js.Constructed).valueBlock
      .value;

    const setBlock = seqInTagged0.find(
      (b) => b.idBlock.tagClass === 1 && b.idBlock.tagNumber === 17
    );

    if (!setBlock) {
      throw new Error("ASN1RouteError");
    }

    const setContent = (setBlock as asn1js.Constructed).valueBlock.value;
    const innerSeq = setContent[0];

    if (!innerSeq) {
      throw new Error("SET is empty");
    }

    if (innerSeq.idBlock.tagNumber !== 16) {
      throw new Error("Expected SEQUENCE as first element of SET");
    }

    const innerSeqContent = (innerSeq as asn1js.Constructed).valueBlock.value;
    const oidBlock = innerSeqContent[0];

    if (!oidBlock) {
      throw new Error("Inner SEQUENCE is empty");
    }

    if (oidBlock.idBlock.tagNumber !== 6) {
      throw new Error(
        "Expected ObjectIdentifier as first element of inner SEQUENCE"
      );
    }

    return oidBlock as ObjectIdentifier;
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
    const buffer = this.sod;

    const asn1Result = asn1js.fromBER(buffer);
    if (asn1Result.offset === -1) {
      throw new Error("ASN1DecodeError: Failed to decode BER data");
    }

    const rootBlock = asn1Result.result;

    if (
      !(rootBlock.idBlock.tagClass === 2 && rootBlock.idBlock.tagNumber === 23)
    ) {
      throw new Error("Expected Application 23 as the root block");
    }

    const app23SeqContent = (rootBlock.valueBlock as any)
      .value as asn1js.BaseBlock[];

    if (!Array.isArray(app23SeqContent)) {
      throw new Error("Expected SEQUENCE inside Application 23");
    }

    const tagged0 = app23SeqContent.find(
      (block) => block.idBlock.tagClass === 3 && block.idBlock.tagNumber === 0
    );

    if (!tagged0) {
      throw new Error("No [0] tagged block found in Application 23 SEQUENCE");
    }

    // Получаем контент (SEQUENCE) внутри [0]
    const innerSeq = (tagged0.valueBlock as any).value as asn1js.BaseBlock[];

    if (!Array.isArray(innerSeq)) {
      throw new Error("Expected SEQUENCE inside [0]");
    }

    // Ищем SET (Tag 17)
    const setBlock = innerSeq.find(
      (block) => block.idBlock.tagClass === 1 && block.idBlock.tagNumber === 17
    );

    if (!setBlock) {
      throw new Error("No SET found inside the main SEQUENCE");
    }

    const setContent = (setBlock.valueBlock as any).value as asn1js.BaseBlock[];
    if (!setContent || setContent.length === 0) {
      throw new Error("SET is empty");
    }

    const outerSequenceBlock = setContent[0];
    if (outerSequenceBlock.idBlock.tagNumber !== 16) {
      throw new Error("Expected SEQUENCE as first element of SET");
    }

    const sequenceContent = (outerSequenceBlock.valueBlock as any)
      .value as asn1js.BaseBlock[];

    if (sequenceContent.length !== 6) {
      throw new Error(
        "SET-nested SEQUENCE did not contain 6 elements (Expected SignedData content)"
      );
    }

    const signatureAlgBlock = sequenceContent[1];

    if (signatureAlgBlock.idBlock.tagNumber !== 16) {
      throw new Error(
        "Expected SEQUENCE (SignatureAlgorithmIdentifier) at index 1"
      );
    }

    const signatureAlgContent = (signatureAlgBlock.valueBlock as any)
      .value as asn1js.BaseBlock[];

    if (!signatureAlgContent || signatureAlgContent.length === 0) {
      throw new Error("Signature Algorithm SEQUENCE is empty");
    }

    const oidBlock = signatureAlgContent[0];

    if (oidBlock.idBlock.tagNumber !== 6) {
      throw new Error(
        "Expected ObjectIdentifier as first element of Signature Algorithm SEQUENCE"
      );
    }

    const oidValue = (
      oidBlock as asn1js.ObjectIdentifier
    ).valueBlock.toString();

    if (!oidValue.startsWith("1.2.840.")) {
      throw new Error("Signature algorithm OID does not start with 1.2.840.");
    }

    return oidValue;
  }

  public extractEncapsulatedContent(): Uint8Array {
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

    const innerSeqContent = (tagged0Block.valueBlock as any)
      .value as asn1js.BaseBlock[];
    if (!Array.isArray(innerSeqContent)) {
      throw new Error("Expected SEQUENCE inside [0]");
    }

    const encapsulatedContentWrapper = innerSeqContent[2];

    if (!encapsulatedContentWrapper) {
      throw new Error("Expected element at index 2 (Encapsulated Content)");
    }

    if (encapsulatedContentWrapper.idBlock.tagNumber !== 16) {
      // Tag 16 = SEQUENCE
      throw new Error("Expected SEQUENCE inside encapsulated_content_wrapper");
    }

    const encapsulatedContentWrapperContent = (
      encapsulatedContentWrapper.valueBlock as any
    ).value as asn1js.BaseBlock[];

    const contentBlock = encapsulatedContentWrapperContent.find(
      (b) => b.idBlock.tagClass === 3 && b.idBlock.tagNumber === 0
    );

    if (!contentBlock) {
      throw new Error("No encapsulated_content block [0] found");
    }

    const fullDer = contentBlock.toBER();
    const fullBytes = new Uint8Array(fullDer);

    const bytesToSkip = 4;

    if (fullBytes.length <= bytesToSkip) {
      throw new Error("Content block is too short or structure is invalid.");
    }

    const rawContentBytes = fullBytes.slice(bytesToSkip);

    return rawContentBytes;
  }

  public extractSignature(): Uint8Array {
    const buffer = this.sod;

    const asn1Result = asn1js.fromBER(buffer);
    if (asn1Result.offset === -1) {
      throw new Error("ASN1DecodeError: Failed to decode BER data");
    }

    const rootBlock = asn1Result.result;

    if (
      !(rootBlock.idBlock.tagClass === 2 && rootBlock.idBlock.tagNumber === 23)
    ) {
      throw new Error("Expected Application 23 as the root block");
    }

    // Получаем контент (SEQUENCE) внутри Application 23
    const app23SeqContent = (rootBlock.valueBlock as any)
      .value as asn1js.BaseBlock[];

    if (!Array.isArray(app23SeqContent)) {
      throw new Error("Expected SEQUENCE inside Application 23");
    }

    const tagged0Block = app23SeqContent.find(
      (block) => block.idBlock.tagClass === 3 && block.idBlock.tagNumber === 0
    );

    if (!tagged0Block) {
      throw new Error("No [0] tagged block found in Application 23 SEQUENCE");
    }

    const innerSeq = (tagged0Block.valueBlock as any)
      .value as asn1js.BaseBlock[];

    if (!Array.isArray(innerSeq)) {
      throw new Error("Expected SEQUENCE inside [0]");
    }

    let sequenceBlock: asn1js.BaseBlock[] | undefined;

    const setBlock = innerSeq.find(
      (block) => block.idBlock.tagClass === 1 && block.idBlock.tagNumber === 17
    );

    if (!setBlock) {
      throw new Error("No SET found inside the main SEQUENCE");
    }

    const setContent = (setBlock.valueBlock as any).value as asn1js.BaseBlock[];

    if (!setContent || setContent.length === 0) {
      throw new Error("SET is empty");
    }

    const outerSequenceBlock = setContent[0];
    if (outerSequenceBlock.idBlock.tagNumber === 16) {
      const content = (outerSequenceBlock.valueBlock as any)
        .value as asn1js.BaseBlock[];

      if (content && content.length === 6) {
        sequenceBlock = innerSeq;
      }
    }

    if (!sequenceBlock) {
      throw new Error(
        "No inner SET containing 6-element SEQUENCE found (SignedData structure)."
      );
    }

    const signatureBlock = sequenceBlock.find(
      (b) => b.idBlock.tagClass === 1 && b.idBlock.tagNumber === 4
    );

    if (!signatureBlock) {
      throw new Error(
        "No OctetString (signature) found in the expected sequence."
      );
    }

    const signatureBuffer = (signatureBlock.valueBlock as asn1js.OctetString)
      .valueBlock.valueHex;

    return new Uint8Array(signatureBuffer);
  }

  getCertificatePem(): asn1js.BaseBlock {
    const buffer = this.sod;

    const asn1Result = asn1js.fromBER(buffer);
    if (asn1Result.offset === -1) {
      throw new Error("ASN1DecodeError: Failed to decode BER data");
    }

    const rootBlock = asn1Result.result;

    if (
      !(rootBlock.idBlock.tagClass === 2 && rootBlock.idBlock.tagNumber === 23)
    ) {
      throw new Error("Expected Application 23 at root");
    }

    const app23SeqContent = (rootBlock.valueBlock as any)
      .value as asn1js.BaseBlock[];
    if (!Array.isArray(app23SeqContent)) {
      throw new Error("Expected SEQUENCE inside Application 23");
    }

    const tagged0 = app23SeqContent.find(
      (block) => block.idBlock.tagClass === 3 && block.idBlock.tagNumber === 0
    );

    if (!tagged0) {
      throw new Error("No [0] tagged block found in Application 23 SEQUENCE");
    }

    const innerSeq = (tagged0.valueBlock as any).value as asn1js.BaseBlock[];

    if (!Array.isArray(innerSeq)) {
      throw new Error("Expected SEQUENCE inside [0]");
    }

    const setBlock = innerSeq.find(
      (block) => block.idBlock.tagClass === 1 && block.idBlock.tagNumber === 17
    );

    if (!setBlock) {
      throw new Error("Could not find SET containing SignedData elements.");
    }

    const setContent = (setBlock.valueBlock as any).value as asn1js.BaseBlock[];
    const signedDataSequence = setContent[0];
    const signedDataElements = (signedDataSequence.valueBlock as any)
      .value as asn1js.BaseBlock[];

    const certificatesContainer = signedDataElements[4];

    if (!certificatesContainer) {
      throw new Error(
        "Element 4 (Certificates) not found in SignedData SEQUENCE."
      );
    }

    if (
      !(
        certificatesContainer.idBlock.tagClass === 3 &&
        certificatesContainer.idBlock.tagNumber === 0
      )
    ) {
      throw new Error("Expected Certificates to be Context-Specific [0].");
    }

    const innerSetBlock = (
      (certificatesContainer.valueBlock as any).value as asn1js.BaseBlock[]
    )[0];

    if (innerSetBlock.idBlock.tagNumber !== 17) {
      throw new Error("Expected SET inside Certificates [0] tag.");
    }

    return innerSetBlock;
  }
}
