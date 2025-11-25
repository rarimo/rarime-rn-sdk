import { useQuery } from "@tanstack/react-query";
import { JsonRpcProvider } from "ethers";
import { useMemo } from "react";
import { DocumentStatus, RarimePassport } from "./RarimoPassport";
import { StateKeeper__factory } from "./types/contracts";
import { NoirCircuitParams } from "./RnNoirModule";

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
  registerContractAddress: string;
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
    const contract = useMemo(() => {
      const provider = new JsonRpcProvider(
        this.config.apiConfiguration.jsonRpcEvmUrl
      );

      return StateKeeper__factory.connect(
        this.config.contractsConfiguration.stateKeeperAddress,
        provider
      );
    }, []);
    const passportKey = passport.getPassportKey();

    const PassportInfo = await useQuery({
      queryKey: ["getPassportInfo"],
      queryFn: async () => {
        const res = await contract.getPassportInfo(passportKey);

        return res;
      },
    });

    console.log(PassportInfo);

    const activeIdentity = PassportInfo.data?.[0].activeIdentity;

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

    if (passportStatus === DocumentStatus.RegisteredWithOtherPk) {
      throw new Error("This document was registred by other Private Key");
    }

    const hash_algo = passport.extractOIDHashBlock(); //TODO

    const hash_lenght = hash_algo.getByteLength();

    const circuit = NoirCircuitParams.fromName("register_light_" + hash_lenght);

    await NoirCircuitParams.downloadTrustedSetup();

    const byteCode = await circuit.downloadByteCode();

    const inputs = {
      pk: "0x" + this.config.userConfiguration.userPrivateKey,
      dg1: Array.from(passport.dataGroup1).map(String),
    };

    const proof = await circuit.prove(JSON.stringify(inputs), byteCode);

    if (!proof) {
      throw new Error(`Proof generation failed for registration proof`);
    }

    throw new Error("TODO: implement registerIdentity()");
  }
}
