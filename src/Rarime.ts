import { JsonRpcProvider } from "ethers";
import { DocumentStatus, RarimePassport } from "./RarimePassport";
import { RegistrationSimple, StateKeeper__factory } from "./types/contracts";
import { NoirCircuitParams, NoirZKProof } from "./RnNoirModule";
import { Platform } from "react-native";
import { HashAlgorithm } from "./helpers/HashAlgorithm";
import { createRegistrationSimpleContract } from "./helpers/contracts";
import { RarimeUtils } from "./RarimeUtils";
import { SignatureAlgorithm } from "./helpers/SignatureAlgorithm";
import { wrapPem } from "./utils";

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

  public async getDocumentStatus(
    passport: RarimePassport
  ): Promise<DocumentStatus> {
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

    const PassportInfo = await contract.getPassportInfo(passportKeyHex);

    const activeIdentity = PassportInfo?.[0].activeIdentity;

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

    if (passportStatus === DocumentStatus.RegisteredWithOtherPk) {
      throw new Error("This document was registered with other Private Key");
    }

    if (passportStatus === DocumentStatus.RegisteredWithThisPk) {
      throw new Error("This document was registered with this Private Key");
    }

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

    return liteRegisterResponseParsed.data.tx_hash;
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
