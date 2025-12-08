export interface Question {
  title: string;
  description?: string;
  variants: string[];
}

export interface VotingCriteria {
  selector: bigint;
  citizenshipWhitelist: bigint[];
  timestampUpperbound: bigint;
  identityCountUpperbound: bigint;
  sex: bigint;
  birthDateLowerbound: bigint;
  birthDateUpperbound: bigint;
  expirationDateLowerbound: bigint;
}

export interface ProposalData {
  id: string;
  proposalSmtAddress: string;
  criteria: VotingCriteria;
  status: bigint;
  startTimestamp: bigint;
  duration: bigint;
  imageCID: string;
  sendVoteContractAddress: string;
  title: string;
  description?: string;
  questions: Question[];
  rankingBased?: boolean;
  votingResults: bigint[][];
}
