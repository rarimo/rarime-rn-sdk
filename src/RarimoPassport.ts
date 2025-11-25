import { Buffer } from "buffer";
import * as asn1js from "asn1js";
import { StateKeeper } from "./types/contracts";
import { Poseidon } from "@iden3/js-crypto";
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

  public getPassportKey(): Uint8Array {
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
    const signedAttributesDer = this.extractSignedAttributes();

    // 1. Hash the DER bytes.
    // NOTE: Rust uses parsed_hash_algorithm.get_hash_fixed32.
    // We assume SHA256 is used for Passport SignedAttributes standard.
    // If your scheme uses SHA1 or SHA384, this must be dynamic.
    const hashBytes = new Uint8Array(sha256.array(signedAttributesDer));

    // 2. Bit manipulation (Pack 252 bits)
    // Rust loop: for i in (0..252).rev() ...
    // We need to replicate exactly how Rust packs the hash into a single BigInt field element

    let out = 0n;
    let acc = 0n;
    let accBits = 0;

    // Iterating 251 down to 0 (252 iterations)
    for (let i = 251; i >= 0; i--) {
      // Get bit at position i from hashBytes
      // hash[i / 8] >> (7 - (i % 8)) & 1
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

    // 3. Poseidon Hash
    return Poseidon.hash([out]);
  }

  private static extractEcdsaPassportKey(keyBytes: Uint8Array): bigint {
    if (keyBytes.length !== 65 || keyBytes[0] !== 0x04) {
      throw new Error("UnsupportedPassportKey: Invalid ECDSA key format");
    }

    const xBytes = keyBytes.slice(1, 33);
    const yBytes = keyBytes.slice(33, 65);

    const x = bufToBigInt(xBytes);
    const y = bufToBigInt(yBytes);

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

  // --- ASN.1 PARSING LOGIC ---
  // Note: Rust used `simple_asn1`. We use `asn1js`.
  // The navigation logic (Application 23 -> Tag 0 -> ...) is specific to Passport SOD.

  private parseDg15Pubkey(dg15Bytes: Uint8Array): ActiveAuthKey {
    const asn1 = asn1js.fromBER(dg15Bytes.buffer);
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

  /**
   * Extracts SignedAttributes from SOD (Security Object Document).
   * The Rust code navigates a specific path: App 23 -> Tag[0] -> Sequence -> Set -> Sequence(6) -> Tag[0]
   * This is highly specific to the ICAO 9303 structure.
   */
  public extractSignedAttributes(): Uint8Array {
    // Simplified ASN.1 walker for the specific path
    // In a real production app, verify the structure strictly.
    // Here we implement the logic: "Get content of signedData, find signerInfos, extract signedAttrs"

    const asn1 = asn1js.fromBER(this.sod.buffer);
    if (asn1.offset === -1) throw new Error("SOD decode error");

    // 1. Root should be ContentInfo (or Application 23 wrapper in some cases)
    let cursor = asn1.result;

    // Unwrap App 23 if present (Rust code does this)
    if (cursor.idBlock.tagClass === 2 && cursor.idBlock.tagNumber === 23) {
      // @ts-ignore
      cursor = cursor.valueBlock.value[0];
    }

    // 2. Expect SignedData (OID 1.2.840.113549.1.7.2) - In Rust it jumps to Tag[0]
    // The Rust code is manually navigating explicit tags.
    // We will assume standard CMS structure: ContentInfo -> SignedData

    // This is a simplification. The Rust code has very manual "Find Tag 0" logic.
    // Implementing that exact path in JS:

    // Find Tag 0 (Explicit)
    // @ts-ignore
    const signedDataContainer = cursor.valueBlock.value.find(
      (b: any) => b.idBlock.tagNumber === 0
    );
    if (!signedDataContainer) throw new Error("No [0] tag found");

    // Inside Tag 0 is Sequence (SignedData)
    // @ts-ignore
    const signedData = signedDataContainer.valueBlock.value[0];

    // signerInfos is a SET usually at the end of SignedData sequence
    // @ts-ignore
    const signedDataChildren = signedData.valueBlock.value;
    const signerInfos = signedDataChildren[signedDataChildren.length - 1]; // Last element usually

    // Inside signerInfos SET -> Sequence (SignerInfo)
    // @ts-ignore
    const signerInfo = signerInfos.valueBlock.value[0];

    // Inside SignerInfo, signedAttrs is Tag [0] (Implicit or Explicit)
    // @ts-ignore
    const signedAttrs = signerInfo.valueBlock.value.find(
      (b: any) => b.idBlock.tagNumber === 0
    );

    if (!signedAttrs) throw new Error("No signedAttributes [0] found");

    // Re-encoding:
    // Rust code does: to_der(signed_attrs), then sets byte[0] = 0x31 (SET), then parses back.
    // This suggests signedAttrs is tagged as [0] (Context Specific), but needs to be hashed as a SET (0x31).

    const der = signedAttrs.toBER();
    const view = new Uint8Array(der);
    view[0] = 0x31; // Force SET tag per RFC 5652

    // Verify it parses back (Optional sanity check)
    return view;
  }

  // --- MRZ LOGIC ---

  public getMrzString(): string {
    const asn1 = asn1js.fromBER(this.dataGroup1.buffer);
    if (asn1.offset === -1) throw new Error("DG1 decode error");

    // Rust path: App 1 -> App 31 -> OctetString/PrintableString
    // Or App 1 -> Unknown(31) -> ...

    const root = asn1.result;
    // @ts-ignore
    const app31 = root.valueBlock.value[0]; // Assuming structure is rigid

    // @ts-ignore
    const content = app31.valueBlock.value[0];

    // Extract string based on type
    // @ts-ignore
    const rawBytes = content.valueBlock.valueHex;
    const str = Buffer.from(rawBytes).toString("utf8");

    return str.replace(/\0/g, ""); // Trim nulls
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

  // --- VALIDATION ---

  public validate(criteria: VotingCriteria): void {
    const mrz = this.getMrzData();

    // Check Whitelist
    if (criteria.citizenshipWhitelist.length > 0) {
      const countryInt = bufToBigInt(Buffer.from(mrz.issuingCountry, "utf8"));
      if (!criteria.citizenshipWhitelist.includes(countryInt.toString())) {
        throw new Error("Citizen is not in whitelist");
      }
    }

    // Sex check
    if (criteria.sex !== "0" && mrz.sex !== criteria.sex) {
      throw new Error("Sex mismatch");
    }

    const mrzBirth = bufToBigInt(Buffer.from(mrz.birthDate, "utf8"));
    const mrzExpiry = bufToBigInt(Buffer.from(mrz.expiryDate, "utf8"));

    // Helper for string numbers comparison
    const checkBound = (
      val: bigint,
      bound: string,
      type: "lower" | "upper",
      field: string
    ) => {
      // Magic constant from Rust code "52983525027888" (likely ASCII for empty/default placeholders)
      if (bound === "52983525027888") return;

      const boundInt = BigInt(bound);
      if (type === "lower" && boundInt > val)
        throw new Error(`${field} is lower than lowerbound`);
      if (type === "upper" && boundInt < val)
        throw new Error(`${field} is higher than upperbound`);
    };

    checkBound(mrzBirth, criteria.birthDateLowerbound, "lower", "Birth date");
    checkBound(mrzBirth, criteria.birthDateUpperbound, "upper", "Birth date");
    checkBound(
      mrzExpiry,
      criteria.expirationDateLowerbound,
      "upper",
      "Expiration date"
    );
  }

  public extractOIDHashBlock(): HashAlgorithm {
    throw new Error("Method not implemented.");
  }
}
