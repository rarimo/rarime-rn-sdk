import { JsonRpcProvider } from "ethers";
import {
  IDCardVoting__factory,
  PoseidonSMT__factory,
  ProposalsState,
  ProposalsState__factory,
} from "./types";
import { ProposalData } from "./types/Polls";
import { BaseVoting } from "./types/contracts/IDCardVoting";
import { Rarime } from "./Rarime";
import { RarimePassport } from "./RarimePassport";
import { Time } from "@distributedlab/tools";

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
    console.log("contractData", contractData);
    const ipfsData = await this.getProposalDataIpfs(contractData[2][4]);
    console.log("ipfsData", ipfsData);
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
    console.log("proposalData", proposalData);
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
    const ipfsResponce = await fetch(
      this.config.apiConfiguration.ipfsUrl + ipfsCid,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    if (!ipfsResponce.ok) {
      throw new Error(`HTTP error ${ipfsResponce.status}}`);
    }

    return ipfsResponce.json();
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
    console.log("smtProof", smtProof);
    return smtProof[2];
  }

  public async validate(
    proposalData: ProposalData,
    passport: RarimePassport,
    rarime: Rarime
  ) {
    let nowTimestamp = new Time().timestamp;

    if (nowTimestamp < proposalData.startTimestamp) {
      console.log("nowTimestamp", nowTimestamp);
      console.log("proposalData.startTimestamp", proposalData.startTimestamp);
      throw new Error("Vouting has not started.");
    }

    if (nowTimestamp > proposalData.startTimestamp + proposalData.duration) {
      console.log("nowTimestamp", nowTimestamp);
      console.log("proposalData.startTimestamp", proposalData.startTimestamp);
      console.log("proposalData.duration", proposalData.duration);
      throw new Error("Vouting has ended.");
    }

    await rarime.validate(proposalData, passport);

    if (await this.isAlreadyVoted(proposalData, rarime)) {
      throw new Error("User is already voted");
    }
  }
}
