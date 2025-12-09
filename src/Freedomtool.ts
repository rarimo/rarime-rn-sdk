import {
  AbiCoder,
  JsonRpcProvider,
  keccak256,
  toBeHex,
  toBigInt,
  zeroPadValue,
} from "ethers";
import {
  IDCardVoting__factory,
  PoseidonSMT__factory,
  ProposalsState,
  ProposalsState__factory,
  QueryProofParams,
  StateKeeper,
} from "./types";
import { ProposalData } from "./types/Polls";
import { BaseVoting } from "./types/contracts/IDCardVoting";
import { Rarime } from "./Rarime";
import { RarimePassport } from "./RarimePassport";
import { Time } from "@distributedlab/tools";
import { createIDCardVotingContract } from "./helpers/contracts";
import { NoirZKProof } from "./RnNoirModule";

export interface FreedomtoolAPIConfiguration {
  ipfsUrl: string;
  votingRelayerUrl: string;
  votingRpcUrl: string;
}

export interface FreedomtoolContractsConfiguration {
  proposalStateAddress: string;
}

export interface FreedomtoolConfiguration {
  contractsConfiguration: FreedomtoolContractsConfiguration;
  apiConfiguration: FreedomtoolAPIConfiguration;
}

export class Freedomtool {
  private config: FreedomtoolConfiguration;

  constructor(config: FreedomtoolConfiguration) {
    this.config = config;
  }

  public async getProposalData(proposalId: string): Promise<ProposalData> {
    const contractData = await this.getProposalDataContract(proposalId);

    const ipfsData = await this.getProposalDataIpfs(contractData[2][4]);

    const proposalCriteria = await this.getProposalCriteria(
      proposalId,
      contractData[2][5][0]
    );

    const proposalData: ProposalData = {
      id: proposalId,
      proposalSmtAddress: contractData[0],
      criteria: {
        selector: proposalCriteria[0],
        citizenshipWhitelist: proposalCriteria[1],
        timestampUpperbound: proposalCriteria[2],
        identityCountUpperbound: proposalCriteria[3],
        sex: proposalCriteria[4],
        birthDateLowerbound: proposalCriteria[5],
        birthDateUpperbound: proposalCriteria[6],
        expirationDateLowerbound: proposalCriteria[7],
      },
      rankingBased: ipfsData.rankingBased ?? false,
      status: contractData[1],
      startTimestamp: contractData[2][0],
      duration: contractData[2][1],
      imageCID: ipfsData.imageCID ?? "",
      sendVoteContractAddress: contractData[2][5][0],
      title: ipfsData.title,
      questions: ipfsData.acceptedOptions,
      votingResults: contractData[3],
      description: ipfsData.description ?? "",
    };

    return proposalData;
  }

  private async getProposalCriteria(
    proposalId: string,
    sendVoteContractAddress: string
  ): Promise<BaseVoting.ProposalRulesStructOutput> {
    const provider = new JsonRpcProvider(
      this.config.apiConfiguration.votingRpcUrl
    );

    const contract = IDCardVoting__factory.connect(
      sendVoteContractAddress,
      provider
    );

    return contract.getProposalRules(proposalId);
  }

  private async getProposalDataContract(
    proposalId: string
  ): Promise<ProposalsState.ProposalInfoStructOutput> {
    const provider = new JsonRpcProvider(
      this.config.apiConfiguration.votingRpcUrl
    );

    const contract = ProposalsState__factory.connect(
      this.config.contractsConfiguration.proposalStateAddress,
      provider
    );

    return contract.getProposalInfo(proposalId);
  }

  private async getProposalDataIpfs(ipfsCid: string): Promise<any> {
    const ipfsResponse = await fetch(
      this.config.apiConfiguration.ipfsUrl + ipfsCid,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    if (!ipfsResponse.ok) {
      throw new Error(`HTTP error ${ipfsResponse.status}`);
    }

    return ipfsResponse.json();
  }

  public async isAlreadyVoted(
    proposalData: ProposalData,
    rarime: Rarime
  ): Promise<boolean> {
    const provider = new JsonRpcProvider(
      this.config.apiConfiguration.votingRpcUrl
    );

    const proposalsState = ProposalsState__factory.connect(
      this.config.contractsConfiguration.proposalStateAddress,
      provider
    );

    const eventId = await proposalsState.getProposalEventId(proposalData.id);

    const nullifier = rarime.getEventNullifier(eventId);

    const poseidonSmt = PoseidonSMT__factory.connect(
      proposalData.proposalSmtAddress,
      provider
    );

    const smtProof = await poseidonSmt.getProof(nullifier);

    return smtProof[2];
  }

  public async validate(
    proposalData: ProposalData,
    passport: RarimePassport,
    rarime: Rarime
  ) {
    let nowTimestamp = new Time().timestamp;

    if (nowTimestamp < proposalData.startTimestamp) {
      throw new Error("Voting has not started.");
    }

    if (nowTimestamp > proposalData.startTimestamp + proposalData.duration) {
      throw new Error("Voting has ended.");
    }

    await rarime.validate(proposalData, passport);

    if (await this.isAlreadyVoted(proposalData, rarime)) {
      throw new Error("User has already voted");
    }
  }

  private getEventData(votes: number[]): string {
    // 2) ABI‑encode as an array of (uint256,uint256) structs
    const abiCoder = AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(["uint256[]"], [votes.map((v) => 1 << v)]);

    // 3) Take keccak256 hash
    const hashHex = keccak256(encoded);

    // 4) Cast to BigInt
    const hashBn = toBigInt(hashHex);

    // 5) Mask down to 248 bits: (1<<248) - 1
    const mask = (BigInt(1) << BigInt(248)) - BigInt(1);
    const truncated = hashBn & mask;

    // 6) Zero‑pad up to 32 bytes (uint256) and return hex
    return zeroPadValue(toBeHex(truncated), 32);
  }

  private async getEventId(proposalData: ProposalData): Promise<bigint> {
    const provider = new JsonRpcProvider(
      this.config.apiConfiguration.votingRpcUrl
    );

    const proposalsState = ProposalsState__factory.connect(
      this.config.contractsConfiguration.proposalStateAddress,
      provider
    );

    return proposalsState.getProposalEventId(proposalData.id);
  }

  private async buildQueryProofParams(
    answers: number[],
    proposalData: ProposalData,
    passportInfo: [
      StateKeeper.PassportInfoStructOutput,
      StateKeeper.IdentityInfoStructOutput
    ]
  ): Promise<QueryProofParams> {
    const ROOT_VALIDITY = 3600n;

    const eventId = await this.getEventId(proposalData);

    const eventData = this.getEventData(answers);

    const timestamp_upperbound =
      passportInfo[1][1] > 0
        ? passportInfo[1][1]
        : proposalData.criteria.timestampUpperbound - ROOT_VALIDITY;

    const queryProofParams: QueryProofParams = {
      eventId: eventId.toString(),
      eventData: eventData,
      selector: proposalData.criteria.selector.toString(),
      timestampLowerbound: "0",
      timestampUpperbound: timestamp_upperbound.toString(),
      identityCountLowerbound: "0",
      identityCountUpperbound:
        proposalData.criteria.identityCountUpperbound.toString(),
      birthDateLowerbound: proposalData.criteria.birthDateLowerbound.toString(),
      birthDateUpperbound: proposalData.criteria.birthDateUpperbound.toString(),
      expirationDateLowerbound:
        proposalData.criteria.expirationDateLowerbound.toString(),
      expirationDateUpperbound: "52983525027888",
      citizenshipMask: "0",
    };

    return queryProofParams;
  }

  private async buildVoteCallData(
    answers: number[],
    proposalData: ProposalData,
    rarime: Rarime,
    passport: RarimePassport,
    queryProof: NoirZKProof,
    passportInfo: [
      StateKeeper.PassportInfoStructOutput,
      StateKeeper.IdentityInfoStructOutput
    ]
  ): Promise<string> {
    const idCardVoting = createIDCardVotingContract(
      proposalData.sendVoteContractAddress,
      new JsonRpcProvider(this.config.apiConfiguration.votingRpcUrl)
    );

    const abiCode = new AbiCoder();
    const userDataEncoded = abiCode.encode(
      ["uint256", "uint256[]", "tuple(uint256,uint256,uint256)"],
      [
        proposalData.id,
        // votes mask
        answers.map((v) => 1 << Number(v)),
        // User payload: (nullifier, citizenship, identity_creation_timestamp)
        [
          "0x" + queryProof.pub_signals[0],
          "0x" + queryProof.pub_signals[6],
          passportInfo[1][1],
        ],
      ]
    );

    const smtProof = await rarime.getSMTProof(passport);

    const txCallData = idCardVoting.contractInterface.encodeFunctionData(
      "executeTD1Noir",
      [
        smtProof.root,
        "0x" + queryProof.pub_signals[14],
        userDataEncoded,
        "0x" + queryProof.proof,
      ]
    );

    return txCallData;
  }

  private async sendRelayerVote(
    txCallData: string,
    proposalData: ProposalData
  ): Promise<string> {
    const sendVoteRequest = {
      data: {
        attributes: {
          tx_data: txCallData,
          destination: proposalData.sendVoteContractAddress,
        },
      },
    };

    const sendVoteResponse = await fetch(
      this.config.apiConfiguration.votingRelayerUrl +
        "/integrations/proof-verification-relayer/v3/vote",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(sendVoteRequest),
      }
    );

    if (!sendVoteResponse.ok) {
      throw new Error(`HTTP error ${sendVoteResponse.status}}`);
    }

    const sendVoteResponseParsed = await sendVoteResponse.json();

    return sendVoteResponseParsed.data.id;
  }

  public async submitVote(
    answers: number[],
    proposalData: ProposalData,
    rarime: Rarime,
    passport: RarimePassport
  ): Promise<string> {
    await this.validate(proposalData, passport, rarime);

    const passportInfo = await rarime.getPassportInfo(passport);

    const queryProofParams = await this.buildQueryProofParams(
      answers,
      proposalData,
      passportInfo
    );

    const queryProof = await rarime.generateQueryProof(
      queryProofParams,
      passport
    );

    const txCallData = await this.buildVoteCallData(
      answers,
      proposalData,
      rarime,
      passport,
      queryProof,
      passportInfo
    );

    const txHash = await this.sendRelayerVote(txCallData, proposalData);

    return txHash;
  }
}
