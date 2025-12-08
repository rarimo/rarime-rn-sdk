import { PRIVATE_KEY, DG1, SOD, DG15 } from "@env";
import {
  Freedomtool,
  FreedomtoolConfiguration,
  QueryProofParams,
  Rarime,
  RarimeConfiguration,
  RarimePassport,
  RarimeUtils,
} from "@rarimo/rarime-rn-sdk";

export async function liteRegistration() {
  const userPrivateKey =
    PRIVATE_KEY && PRIVATE_KEY.length > 0 ? PRIVATE_KEY : "";

  console.log(userPrivateKey);

  const rarimeConfig: RarimeConfiguration = {
    contractsConfiguration: {
      stateKeeperAddress: "0x12883d5F530AF7EC2adD7cEC29Cf84215efCf4D8",
      registerSimpleContractAddress:
        "0x1b6ae4b80F0f26DC53731D1d7aA31fc3996B513B",
      poseidonSmtAddress: "0xb8bAac4C443097d697F87CC35C5d6B06dDe64D60",
    },
    apiConfiguration: {
      jsonRpcEvmUrl: "https://rpc.qtestnet.org",
      rarimeApiUrl: "https://api.orgs.app.stage.rarime.com",
    },
    userConfiguration: {
      userPrivateKey: userPrivateKey,
    },
  };

  console.log(rarimeConfig);

  const rarime = new Rarime(rarimeConfig);

  const passport = new RarimePassport({
    dataGroup1: DG1 ? Buffer.from(DG1, "base64") : Buffer.from("", "base64"),
    sod: SOD ? Buffer.from(SOD, "base64") : Buffer.from("", "base64"),
    ...(DG15 && DG15.length > 0
      ? { dataGroup15: Buffer.from(DG15, "base64") }
      : {}),
  });

  console.log("passport", passport);

  const pub_key = passport.getPassportKey();
  console.log("Pub key: ", pub_key);

  const liteRegisterResult = await rarime.registerIdentity(passport);
  console.log("liteRegisterResult", liteRegisterResult);

  return liteRegisterResult;
}

export async function generateQueryProof() {
  const userPrivateKey =
    PRIVATE_KEY && PRIVATE_KEY.length > 0
      ? PRIVATE_KEY
      : RarimeUtils.generateBJJPrivateKey();

  console.log(userPrivateKey);

  const rarimeConfig: RarimeConfiguration = {
    contractsConfiguration: {
      stateKeeperAddress: "0x12883d5F530AF7EC2adD7cEC29Cf84215efCf4D8",
      registerSimpleContractAddress:
        "0x1b6ae4b80F0f26DC53731D1d7aA31fc3996B513B",
      poseidonSmtAddress: "0xb8bAac4C443097d697F87CC35C5d6B06dDe64D60",
    },
    apiConfiguration: {
      jsonRpcEvmUrl: "https://rpc.qtestnet.org",
      rarimeApiUrl: "https://api.orgs.app.stage.rarime.com",
    },
    userConfiguration: {
      userPrivateKey: userPrivateKey,
    },
  };

  console.log(rarimeConfig);

  const rarime = new Rarime(rarimeConfig);

  const passport = new RarimePassport({
    dataGroup1: DG1 ? Buffer.from(DG1, "base64") : Buffer.from("", "base64"),
    sod: SOD ? Buffer.from(SOD, "base64") : Buffer.from("", "base64"),
    ...(DG15 && DG15.length > 0
      ? { dataGroup15: Buffer.from(DG15, "base64") }
      : {}),
  });

  console.log("passport", passport);

  const queryProofParams: QueryProofParams = {
    eventId: "43580365239758335475",
    eventData:
      "270038666511201875208172000617689023489105079510191335498520083214634616239",
    selector: "0",
    timestampLowerbound: "0",
    timestampUpperbound: "0",
    identityCountLowerbound: "0",
    identityCountUpperbound: "0",
    birthDateLowerbound: "52983525027888",
    birthDateUpperbound: "52983525027888",
    expirationDateLowerbound: "52983525027888",
    expirationDateUpperbound: "52983525027888",
    citizenshipMask: "0",
  };

  const queryProof = await rarime.generateQueryProof(
    queryProofParams,
    passport
  );

  console.log("queryProof", queryProof);

  return queryProof;
}

export async function getPollsData() {
  const freedomtoolConfig: FreedomtoolConfiguration = {
    contractsConfiguration: {
      proposalStateAddress: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b",
    },
    apiConfiguration: {
      ipfsUrl: "https://ipfs.rarimo.com/ipfs/",
      votingRelayerUrl: "",
      votingRpcUrl: "https://rpc.qtestnet.org",
    },
  };

  const proposalId = "218";
  console.log("proposalId ", proposalId);

  const freedomtool = new Freedomtool(freedomtoolConfig);

  return freedomtool.getProposalData(proposalId);
}

export async function isAlreadyVoted(): Promise<boolean> {
  const userPrivateKey =
    PRIVATE_KEY && PRIVATE_KEY.length > 0 ? PRIVATE_KEY : "";

  console.log(userPrivateKey);

  const freedomtoolConfig: FreedomtoolConfiguration = {
    contractsConfiguration: {
      proposalStateAddress: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b",
    },
    apiConfiguration: {
      ipfsUrl: "https://ipfs.rarimo.com/ipfs/",
      votingRelayerUrl: "",
      votingRpcUrl: "https://rpc.qtestnet.org",
    },
  };

  const proposalId = "218";
  console.log("proposalId ", proposalId);

  const freedomtool = new Freedomtool(freedomtoolConfig);

  const rarimeConfig: RarimeConfiguration = {
    contractsConfiguration: {
      stateKeeperAddress: "0x12883d5F530AF7EC2adD7cEC29Cf84215efCf4D8",
      registerSimpleContractAddress:
        "0x1b6ae4b80F0f26DC53731D1d7aA31fc3996B513B",
      poseidonSmtAddress: "0xb8bAac4C443097d697F87CC35C5d6B06dDe64D60",
    },
    apiConfiguration: {
      jsonRpcEvmUrl: "https://rpc.qtestnet.org",
      rarimeApiUrl: "https://api.orgs.app.stage.rarime.com",
    },
    userConfiguration: {
      userPrivateKey: userPrivateKey,
    },
  };

  console.log("rarimeConfig", rarimeConfig);

  const rarime = new Rarime(rarimeConfig);
  const proposalData = await freedomtool.getProposalData(proposalId);

  return freedomtool.isAlreadyVoted(proposalData, rarime);
}
