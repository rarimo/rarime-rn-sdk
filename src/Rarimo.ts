import { JsonRpcProvider, toUtf8Bytes } from "ethers";
import { DocumentStatus, RarimePassport } from "./RarimoPassport";
import { RegistrationSimple, StateKeeper__factory } from "./types/contracts";
import { NoirCircuitParams } from "./RnNoirModule";
import { Platform } from "react-native";
import { HashAlgorithm } from "./helpers/HashAlgorithm";
import { createRegistrationSimpleContract } from "./helpers/contracts";
import { RarimeUtils } from "./RarimeUtils";
import { SignatureAlgorithm } from "./helpers/SignatureAlgorith";
import { wrapPem } from "./utils";

const ZERO_BYTES = new Uint8Array(32);

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
    console.log(passportKey);

    const passportKeyHex = passportKey.toString(16);

    console.log("PassportKeyHex:", passportKeyHex);

    const passportKeyBytes = toUtf8Bytes(passportKeyHex);

    console.log(Buffer.from(passportKeyBytes).toString("hex"));

    const PassportInfo = await contract.getPassportInfo(passportKeyBytes.slice(0, 32));
    console.log(PassportInfo);

    const activeIdentity = PassportInfo?.[0].activeIdentity;

    const ZERO_BYTES_STRING = Array.from(ZERO_BYTES)
      .map((b) => b.toString(16).padStart(2, "0"))
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
    console.log(passportStatus);
    // if (passportStatus === DocumentStatus.RegisteredWithOtherPk) {
    //   throw new Error("This document was registred by other Private Key");
    // }

    if (passportStatus === DocumentStatus.RegisteredWithThisPk) {
      throw new Error("This document was registred by this Private Key");
    }

    const hashAlgoOID = passport.extractDGHashAlgo();

    console.log(hashAlgoOID);

    const hashAlgo = HashAlgorithm.fromOID(hashAlgoOID);

    const hashLength = hashAlgo.getByteLength();

    const circuit = NoirCircuitParams.fromName("register_light_" + hashLength);

    await NoirCircuitParams.downloadTrustedSetup();

    const byteCode = await circuit.downloadByteCode();

    let inputs = {
      pk: this.config.userConfiguration.userPrivateKey,
      dg1: Array.from(passport.dataGroup1).map(String),
    };

    if (Platform.OS === "android") {
      inputs = {
        pk: "0x" + this.config.userConfiguration.userPrivateKey,
        dg1: Array.from(passport.dataGroup1).map(String),
      };
    }

    const proof = await circuit.prove(JSON.stringify(inputs), byteCode);

    if (!proof) {
      throw new Error(`Proof generation failed for registration proof`);
    }
    console.log(proof);

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
            hashAlgorithm: HashAlgorithm.fromOID(
              passport.getDgHashAlgorithm()
            ).toString(),
            signatureAlgorithm: SignatureAlgorithm.fromOID(
              passport.getSignatureAlgorithm()
            ).toString(),
            signedAttributes: Buffer.from(
              passport.extractSignedAttributes()
            ).toString("hex"),
            encapsulatedContent: Buffer.from(
              passport.extractEncapsulatedContent()
            ).toString("hex"),
            signature: Buffer.from(passport.extractSignature()).toString("hex"),
            pemFile: wrapPem(passport.getCertificatePem()),
            dg15: passport.dataGroup15
              ? Buffer.from(passport.dataGroup15).toString("hex")
              : "",
            AASignature: passport.aaSignature
              ? Buffer.from(passport.aaSignature).toString("hex")
              : "",
            sod: Buffer.from(passport.sod).toString("hex"),
          },
          zkProof: Buffer.from(proofBytes).toString("base64"),
        },
      },
    };

    console.log(verifySodRequest);

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
      const errorData = await verifySodResponse.json();
      throw new Error(
        `HTTP error ${verifySodResponse.status}: ${JSON.stringify(errorData)}`
      );
    }

    const verifySodResponseParsed = await verifySodResponse.json();

    const registrationSimpleContract = createRegistrationSimpleContract(
      this.config.contractsConfiguration.registerSimpleContractAddress,
      new JsonRpcProvider(this.config.apiConfiguration.jsonRpcEvmUrl)
    );

    const passportStruct: RegistrationSimple.PassportStruct = {
      dgCommit: proof.pub_signals[0],
      dg1Hash: "0x" + proof.pub_signals[1],
      publicKey: toUtf8Bytes(
        verifySodResponseParsed.data.attributes.public_key
      ).slice(0, 32),
      passportHash: "0x" + proof.pub_signals[2],
      verifier: verifySodResponseParsed.data.attributes.verifier, //if not work strip "0x" prefix
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
          proof.proof,
        ]
      );
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

    const liteRegisterResponseParsed = await liteRegisterResponse.json();

    return liteRegisterResponseParsed.data.tx_hash;
  }
}
