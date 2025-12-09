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
import { ProposalData, ProposalQuestion } from "./types/proposal";
import { BaseVoting } from "./types/contracts/IDCardVoting";
import { Rarime } from "./Rarime";
import { RarimePassport } from "./RarimePassport";
import { Time } from "@distributedlab/tools";
import { createIDCardVotingContract } from "./helpers/contracts";
import { NoirZKProof } from "./RnNoirModule";

export interface FreedomToolAPIConfiguration {
  ipfsUrl: string;
  votingRelayerUrl: string;
  votingRpcUrl: string;
}

export interface SubmitProposalParams {
  answers: number[];
  proposalData: ProposalData;
  rarime: Rarime;
  passport: RarimePassport;
}

interface IPFSProposalMetadata {
  title: string;
  description?: string;
  acceptedOptions: ProposalQuestion[];
  imageCid?: string;
  rankingBased?: boolean;
}

export interface FreedomToolContractsConfiguration {
  proposalStateAddress: string;
}

export interface FreedomToolConfiguration {
  contracts: FreedomToolContractsConfiguration;
  api: FreedomToolAPIConfiguration;
}

export class FreedomTool {
  private config: FreedomToolConfiguration;

  constructor(config: FreedomToolConfiguration) {
    this.config = config;
  }

  public async getProposalData(proposalId: string): Promise<ProposalData> {
    const contractData = await this.getProposalDataFromContracts(proposalId);

    const ipfsData = await this.getProposalDataFromIpfs(contractData[2][4]);

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
      startTimestamp: contractData[2][0],
      duration: contractData[2][1],
      imageCID: ipfsData.imageCid ?? "",
      sendVoteContractAddress: contractData[2][5][0],
      title: ipfsData.title,
      questions: ipfsData.acceptedOptions,
      votingResults: contractData[3],
      description: ipfsData.description ?? "",
    };

    return proposalData;
  }

  public async isAlreadyVoted(
    proposalData: ProposalData,
    rarime: Rarime
  ): Promise<boolean> {
    const provider = new JsonRpcProvider(this.config.api.votingRpcUrl);

    const proposalsState = ProposalsState__factory.connect(
      this.config.contracts.proposalStateAddress,
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

  public async verify(
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

    await rarime.validateIdentity(proposalData, passport);

    if (await this.isAlreadyVoted(proposalData, rarime)) {
      throw new Error("User has already voted");
    }
  }

  public async submitProposal({
    answers,
    proposalData,
    rarime,
    passport,
  }: SubmitProposalParams): Promise<string> {
    await this.verify(proposalData, passport, rarime);

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

    const txCallData = await this.buildProposalCallData(
      answers,
      proposalData,
      rarime,
      passport,
      queryProof,
      passportInfo
    );

    const txHash = await this.sendProposalRequest(txCallData, proposalData);

    return txHash;
  }

  private async getProposalCriteria(
    proposalId: string,
    sendVoteContractAddress: string
  ): Promise<BaseVoting.ProposalRulesStructOutput> {
    const provider = new JsonRpcProvider(this.config.api.votingRpcUrl);

    const contract = IDCardVoting__factory.connect(
      sendVoteContractAddress,
      provider
    );

    return contract.getProposalRules(proposalId);
  }

  private async getProposalDataFromContracts(
    proposalId: string
  ): Promise<ProposalsState.ProposalInfoStructOutput> {
    const provider = new JsonRpcProvider(this.config.api.votingRpcUrl);

    const contract = ProposalsState__factory.connect(
      this.config.contracts.proposalStateAddress,
      provider
    );

    return contract.getProposalInfo(proposalId);
  }

  private async getProposalDataFromIpfs(
    ipfsCid: string
  ): Promise<IPFSProposalMetadata> {
    const ipfsResponse = await fetch(this.config.api.ipfsUrl + ipfsCid, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (!ipfsResponse.ok) {
      throw new Error(`HTTP error ${ipfsResponse.status}`);
    }

    return ipfsResponse.json();
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
    const provider = new JsonRpcProvider(this.config.api.votingRpcUrl);

    const proposalsState = ProposalsState__factory.connect(
      this.config.contracts.proposalStateAddress,
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

  private async buildProposalCallData(
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
      new JsonRpcProvider(this.config.api.votingRpcUrl)
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

  private async sendProposalRequest(
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
      this.config.api.votingRelayerUrl +
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
}
