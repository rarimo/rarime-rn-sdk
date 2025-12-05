import { hexlify, JsonRpcProvider, toUtf8Bytes } from "ethers";
import { DocumentStatus, RarimePassport } from "./RarimePassport";
import {
  PoseidonSMT__factory,
  RegistrationSimple,
  StateKeeper,
  StateKeeper__factory,
} from "./types/contracts";
import { NoirCircuitParams, NoirZKProof } from "./RnNoirModule";
import { Platform } from "react-native";
import { HashAlgorithm } from "./helpers/HashAlgorithm";
import { createRegistrationSimpleContract } from "./helpers/contracts";
import { RarimeUtils } from "./RarimeUtils";
import { SignatureAlgorithm } from "./helpers/SignatureAlgorithm";
import { wrapPem } from "./utils";
import { QueryProofParams } from "./types";
import { SparseMerkleTree } from "./types/contracts/PoseidonSMT";
import { Poseidon } from "@iden3/js-crypto";
import { Time } from "@distributedlab/tools";

const ZERO_BYTES = new Uint8Array(64);

export interface RarimeUserConfiguration {
  userPrivateKey: string;
}

export interface RarimeAPIConfiguration {
  jsonRpcEvmUrl: string;
  rarimeApiUrl: string;
}

export interface RarimeContractsConfiguration {
  stateKeeperAddress: string;
  registerSimpleContractAddress: string;
  poseidonSmtAddress: string;
}

export interface RarimeConfiguration {
  contractsConfiguration: RarimeContractsConfiguration;
  apiConfiguration: RarimeAPIConfiguration;
  userConfiguration: RarimeUserConfiguration;
}

export class Rarime {
  private config: RarimeConfiguration;

  constructor(config: RarimeConfiguration) {
    if (config.userConfiguration.userPrivateKey.startsWith("0x")) {
      config.userConfiguration.userPrivateKey =
        config.userConfiguration.userPrivateKey.slice(2);
    }

    if (config.userConfiguration.userPrivateKey.length !== 64) {
      throw new Error("Not valid private key");
    }

    this.config = config;
  }

  private async getPassportInfo(
    passport: RarimePassport
  ): Promise<
    [StateKeeper.PassportInfoStructOutput, StateKeeper.IdentityInfoStructOutput]
  > {
    const provider = new JsonRpcProvider(
      this.config.apiConfiguration.jsonRpcEvmUrl
    );

    const contract = StateKeeper__factory.connect(
      this.config.contractsConfiguration.stateKeeperAddress,
      provider
    );

    const passportKey = passport.getPassportKey();

    let passportKeyHex = passportKey.toString(16).padStart(64, "0");

    if (!passportKeyHex.startsWith("0x")) {
      passportKeyHex = "0x" + passportKeyHex;
    }

    const passportInfo = await contract.getPassportInfo(passportKeyHex);
    return passportInfo;
  }

  public async getDocumentStatus(
    passport: RarimePassport
  ): Promise<DocumentStatus> {
    const passportInfo = await this.getPassportInfo(passport);

    const activeIdentity = passportInfo?.[0].activeIdentity;

    const ZERO_BYTES_STRING =
      "0x" +
      Array.from(ZERO_BYTES)
        .map((b) => b.toString(16))
        .join("");
    if (activeIdentity === ZERO_BYTES_STRING) {
      return DocumentStatus.NotRegistered;
    }

    if (activeIdentity === this.config.userConfiguration.userPrivateKey) {
      return DocumentStatus.RegisteredWithThisPk;
    }

    return DocumentStatus.RegisteredWithOtherPk;
  }

  public async registerIdentity(passport: RarimePassport): Promise<String> {
    const passportStatus = await this.getDocumentStatus(passport);

    // if (passportStatus === DocumentStatus.RegisteredWithOtherPk) {
    //   throw new Error("This document was registered with other Private Key");
    // }

    // if (passportStatus === DocumentStatus.RegisteredWithThisPk) {
    //   throw new Error("This document was registered with this Private Key");
    // }

    const hashAlgoOID = passport.extractDGHashAlgo();

    const hashAlgo = HashAlgorithm.fromOID(hashAlgoOID);

    const hashLength = hashAlgo.getByteLength();

    const proof = await this.generateLiteRegisterProof(hashLength, passport);

    const verifySodResponse = await this.verifySodRequest(passport, proof);

    const verifySodResponseParsed = await verifySodResponse.json();

    const txCallData = this.buildLiteRegisterCalldata(
      verifySodResponseParsed,
      proof,
      passport
    );

    const liteRegisterResponse = await this.sendRegisterLiteTransaction(
      txCallData
    );

    const liteRegisterResponseParsed = await liteRegisterResponse.json();
    console.log("liteRegisterResponseParsed", liteRegisterResponseParsed);
    return liteRegisterResponseParsed.data.id;
  }

  private buildLiteRegisterCalldata(
    verifySodResponseParsed: any,
    proof: NoirZKProof,
    passport: RarimePassport
  ): string {
    const registrationSimpleContract = createRegistrationSimpleContract(
      this.config.contractsConfiguration.registerSimpleContractAddress,
      new JsonRpcProvider(this.config.apiConfiguration.jsonRpcEvmUrl)
    );

    const passportStruct: RegistrationSimple.PassportStruct = {
      dgCommit: BigInt("0x" + proof.pub_signals[0]),
      dg1Hash: Buffer.from(proof.pub_signals[1], "hex"),
      publicKey: verifySodResponseParsed.data.attributes.public_key,
      passportHash:
        "0x" + passport.getPassportHash().toString(16).padStart(64, "0"),
      verifier: verifySodResponseParsed.data.attributes.verifier,
    };

    const txCallData =
      registrationSimpleContract.contractInterface.encodeFunctionData(
        "registerSimpleViaNoir",
        [
          "0x" +
            RarimeUtils.getProfileKey(
              this.config.userConfiguration.userPrivateKey
            ),
          passportStruct,
          verifySodResponseParsed.data.attributes.signature,
          "0x" + proof.proof,
        ]
      );

    return txCallData;
  }

  private async generateLiteRegisterProof(
    hashLength: number,
    passport: RarimePassport
  ): Promise<NoirZKProof> {
    const circuit = NoirCircuitParams.fromName("register_light_" + hashLength);

    await NoirCircuitParams.downloadTrustedSetup();

    const byteCode = await circuit.downloadByteCode();

    let inputs = {
      dg1: NoirCircuitParams.formatArray(
        Array.from(passport.dataGroup1).map((byteValue) =>
          byteValue.toString()
        ),
        false
      ),
      sk_identity: "0x" + this.config.userConfiguration.userPrivateKey,
    };

    if (Platform.OS === "android") {
      inputs = {
        dg1: NoirCircuitParams.formatArray(
          Array.from(passport.dataGroup1).map((byteValue) =>
            byteValue.toString()
          ),
          true
        ),
        sk_identity: "0x" + this.config.userConfiguration.userPrivateKey,
      };
    }

    const proof = await circuit.prove(JSON.stringify(inputs), byteCode);

    if (!proof) {
      throw new Error(`Proof generation failed for registration proof`);
    }

    return proof;
  }

  private getSMTProofIndex(passport: RarimePassport): string {
    const passportKey = passport.getPassportKey();
    console.log("passportKey", passportKey);
    const profileKey = RarimeUtils.getProfileKey(
      this.config.userConfiguration.userPrivateKey
    );
    console.log("profileKey", profileKey);

    const poseidonHash = Poseidon.hash([
      passportKey,
      BigInt("0x" + profileKey),
    ]);

    console.log("poseidonHash", poseidonHash);

    return "0x" + poseidonHash.toString(16).padStart(64, "0");
  }

  private async getSMTProof(
    passport: RarimePassport
  ): Promise<SparseMerkleTree.ProofStruct> {
    const provider = new JsonRpcProvider(
      this.config.apiConfiguration.jsonRpcEvmUrl
    );

    const contract = PoseidonSMT__factory.connect(
      this.config.contractsConfiguration.poseidonSmtAddress,
      provider
    );
    console.log("contract");
    const smtProofIndex = this.getSMTProofIndex(passport);
    console.log("smtProofIndex", smtProofIndex);
    const smtProof = await contract.getProof(smtProofIndex);

    return smtProof;
  }

  public async generateQueryProof(
    queryProofParams: QueryProofParams,
    passport: RarimePassport
  ): Promise<NoirZKProof> {
    const circuit = NoirCircuitParams.fromName("query_identity");
    console.log("circuit", circuit);
    await NoirCircuitParams.downloadTrustedSetup();

    const byteCode = await circuit.downloadByteCode();

    const profileKey =
      "0x" +
      RarimeUtils.getProfileKey(this.config.userConfiguration.userPrivateKey);

    const passportInfo = await this.getPassportInfo(passport);

    if (profileKey != passportInfo[0].activeIdentity) {
      throw new Error(
        `profile key mismatch. profileKey = ${profileKey}, passportInfo.activeIdentity = ${passportInfo[0].activeIdentity}`
      );
    }

    const smtProof = await this.getSMTProof(passport);
    console.log("smtProof", smtProof);
    
    let inputs = {
      event_id: queryProofParams.eventId, //from input
      event_data: queryProofParams.eventData,
      id_state_root: smtProof.root, //from SMT
      selector: queryProofParams.selector, //from input
      current_date: hexlify(toUtf8Bytes(new Time().format("YYMMDD"))),
      timestamp_lowerbound: queryProofParams.timestampLowerbound, //from input
      timestamp_upperbound: queryProofParams.timestampUpperbound, //from input
      identity_count_lowerbound: queryProofParams.identityCountLowerbound, //from input
      identity_count_upperbound: queryProofParams.identityCountUpperbound, //from input
      birth_date_lowerbound: queryProofParams.birthDateLowerbound, //from input
      birth_date_upperbound: queryProofParams.birthDateUpperbound, //from input
      expiration_date_lowerbound: queryProofParams.expirationDateLowerbound, //from input
      expiration_date_upperbound: queryProofParams.expirationDateUpperbound, //from input
      citizenship_mask: queryProofParams.citizenshipMask, //from input
      sk_identity: "0x" + this.config.userConfiguration.userPrivateKey,
      pk_passport_hash: passport.getPassportKey(),
      dg1: NoirCircuitParams.formatArray(
        Array.from(passport.dataGroup1).map((byteValue) =>
          byteValue.toString()
        ),
        true
      ),
      siblings: smtProof.siblings, //from SMT
      timestamp: passportInfo[1].issueTimestamp,
      identity_counter: passportInfo[0].identityReissueCounter,
    };

    if (Platform.OS === "android") {
      inputs = {
        event_id: queryProofParams.eventId, //from input
        event_data: queryProofParams.eventData,
        id_state_root: smtProof.root, //from SMT
        selector: queryProofParams.selector, //from input
        current_date: hexlify(toUtf8Bytes(new Time().format("YYMMDD"))),
        timestamp_lowerbound: queryProofParams.timestampLowerbound, //from input
        timestamp_upperbound: queryProofParams.timestampUpperbound, //from input
        identity_count_lowerbound: queryProofParams.identityCountLowerbound, //from input
        identity_count_upperbound: queryProofParams.identityCountUpperbound, //from input
        birth_date_lowerbound: queryProofParams.birthDateLowerbound, //from input
        birth_date_upperbound: queryProofParams.birthDateUpperbound, //from input
        expiration_date_lowerbound: queryProofParams.expirationDateLowerbound, //from input
        expiration_date_upperbound: queryProofParams.expirationDateUpperbound, //from input
        citizenship_mask: queryProofParams.citizenshipMask, //from input
        sk_identity: "0x" + this.config.userConfiguration.userPrivateKey,
        pk_passport_hash: passport.getPassportKey(),
        dg1: NoirCircuitParams.formatArray(
          Array.from(passport.dataGroup1).map((byteValue) =>
            byteValue.toString()
          ),
          true
        ),
        siblings: smtProof.siblings, //from SMT
        timestamp: passportInfo[1].issueTimestamp,
        identity_counter: passportInfo[0].identityReissueCounter,
      };
    }

    const proof = await circuit.prove(JSON.stringify(inputs), byteCode);

    if (!proof) {
      throw new Error(`Proof generation failed for registration proof`);
    }

    return proof;
  }

  private async verifySodRequest(
    passport: RarimePassport,
    proof: NoirZKProof
  ): Promise<Response> {
    const pubSignalsBuffers = proof.pub_signals.map((sig) =>
      Buffer.from(sig, "hex")
    );

    const proofBuffer = Buffer.from(proof.proof, "hex");

    const proofBytes = Buffer.concat([...pubSignalsBuffers, proofBuffer]);

    const verifySodRequest = {
      data: {
        id: "",
        type_field: "register",
        attributes: {
          document_sod: {
            hash_algorithm: HashAlgorithm.fromOID(
              passport.extractDGHashAlgo()
            ).toString(),
            signature_algorithm: SignatureAlgorithm.fromOID(
              passport.getSignatureAlgorithm()
            ).toString(),
            signed_attributes:
              "0x" +
              Buffer.from(passport.extractSignedAttributes()).toString("hex"),
            encapsulated_content:
              "0x" +
              Buffer.from(passport.extractEncapsulatedContent()).toString(
                "hex"
              ),
            signature:
              "0x" + Buffer.from(passport.extractSignature()).toString("hex"),
            pem_file: wrapPem(passport.getCertificate()),
            dg15: passport.dataGroup15
              ? "0x" + Buffer.from(passport.dataGroup15).toString("hex")
              : "",
            aa_signature: passport.aaSignature
              ? "0x" + Buffer.from(passport.aaSignature).toString("hex")
              : "",
            sod: "0x" + Buffer.from(passport.sod).toString("hex"),
          },
          zk_proof: Buffer.from(proofBytes).toString("base64"),
        },
      },
    };

    const verifySodResponse = await fetch(
      this.config.apiConfiguration.rarimeApiUrl +
        "/integrations/incognito-light-registrator/v1/registerid",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(verifySodRequest),
      }
    );

    if (!verifySodResponse.ok) {
      throw new Error(`HTTP error ${verifySodResponse.status}}`);
    }

    return verifySodResponse;
  }

  private async sendRegisterLiteTransaction(
    txCallData: string
  ): Promise<Response> {
    const lite_register_request = {
      data: {
        tx_data: txCallData,
        no_send: false,
        destination:
          this.config.contractsConfiguration.registerSimpleContractAddress,
      },
    };

    const liteRegisterResponse = await fetch(
      this.config.apiConfiguration.rarimeApiUrl +
        "/integrations/registration-relayer/v1/register",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(lite_register_request),
      }
    );

    if (!liteRegisterResponse.ok) {
      const errorData = await liteRegisterResponse.json();
      throw new Error(
        `HTTP error ${liteRegisterResponse.status}: ${JSON.stringify(
          errorData
        )}`
      );
    }

    return liteRegisterResponse;
  }
}
