/**
 * Proof input parameters for QueryIdentityCircuit.
 */
export interface QueryProofParams {
  eventId?: string;
  eventData?: string;
  idStateRoot?: string;
  selector?: string;
  timestampLower?: string;
  timestampUpper?: string;
  timestamp?: string;
  identityCounter?: string;
  identityCountLower?: string;
  identityCountUpper?: string;
  birthDateLower?: string;
  birthDateUpper?: string;
  expirationDateLower?: string;
  expirationDateUpper?: string;
  citizenshipMask?: string;
  skIdentity?: string;
  pkPassportHash?: string;
  currentDate?: string;
  dg1?: string[]; // array of byte values as strings
  siblings?: string[]; // array of branch nodes
}
