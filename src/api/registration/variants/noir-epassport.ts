import { NoirZKProof } from "@modules/noir";
import { hexlify, keccak256 } from "ethers";

import { relayerRegister } from "@/api/modules/registration/relayer";
import {
  PassportInfo,
  RegistrationStrategy,
} from "@/api/modules/registration/strategy";
import { tryCatch } from "@/helpers/try-catch";
import { PassportRegisteredWithAnotherPKError } from "@/store/modules/identity/errors";
import {
  IdentityItem,
  NoirEpassportIdentity,
} from "@/store/modules/identity/Identity";
import { SparseMerkleTree } from "@/types/contracts/PoseidonSMT";
import { Registration2 } from "@/types/contracts/Registration";
import { NoirEPassportBasedRegistrationCircuit } from "@/utils/circuits/registration/noir-registration-circuit";
import { EDocument, EPassport } from "@/utils/e-document/e-document";

export class NoirEPassportRegistration extends RegistrationStrategy {
  buildRegisterCallData = async (
    identityItem: NoirEpassportIdentity,
    slaveCertSmtProof: SparseMerkleTree.ProofStructOutput,
    isRevoked: boolean
  ) => {
    if (typeof identityItem.registrationProof !== "string") {
      throw new TypeError(
        "Noir proof is not supported for Circom registration"
      );
    }

    const registrationProof = identityItem.registrationProof as NoirZKProof;
    const identityItemDocument = identityItem.document as EPassport;

    const circuit = new NoirEPassportBasedRegistrationCircuit(
      identityItemDocument
    );

    const aaSignature = identityItemDocument.getAASignature();

    if (!aaSignature) throw new TypeError("AA signature is not defined");

    const parts = circuit.name.split("_");

    if (parts.length < 2) {
      throw new Error("circuit name is in invalid format");
    }

    // ZKTypePrefix represerts the circuit zk type prefix
    const ZKTypePrefix = "Z_PER_PASSPORT";

    const zkTypeSuffix = parts.slice(1).join("_"); // support for multi-underscore suffix
    const zkTypeName = `${ZKTypePrefix}_${zkTypeSuffix}`;

    const passport: Registration2.PassportStruct = {
      dataType: identityItemDocument.getAADataType(
        circuit.eDoc.sod.slaveCertificate.keySize
      ),
      zkType: keccak256(zkTypeName),
      signature: aaSignature,
      publicKey: (() => {
        const aaPublicKey = identityItemDocument.getAAPublicKey();

        if (!aaPublicKey) return identityItem.publicKey;

        return aaPublicKey;
      })(),
      passportHash: identityItem.passportHash,
    };

    if (isRevoked) {
      return RegistrationStrategy.registrationContractInterface.encodeFunctionData(
        "reissueIdentityViaNoir",
        [
          slaveCertSmtProof.root,
          identityItem.pkIdentityHash,
          identityItem.dg1Commitment,
          passport,
          registrationProof.proof,
        ]
      );
    }

    return RegistrationStrategy.registrationContractInterface.encodeFunctionData(
      "registerViaNoir",
      [
        slaveCertSmtProof.root,
        identityItem.pkIdentityHash,
        identityItem.dg1Commitment,
        passport,
        registrationProof.proof,
      ]
    );
  };

  createIdentity = async (
    _eDocument: EDocument,
    privateKey: string,
    publicKeyHash: Uint8Array
  ): Promise<NoirEpassportIdentity> => {
    const eDocument = _eDocument as EPassport;

    const CSCACertBytes = await RegistrationStrategy.retrieveCSCAFromPem();

    const slaveMaster = await eDocument.sod.slaveCertificate.getSlaveMaster(
      CSCACertBytes
    );

    const slaveCertSmtProof = await RegistrationStrategy.getSlaveCertSmtProof(
      eDocument.sod.slaveCertificate
    );

    if (!slaveCertSmtProof.existence) {
      await RegistrationStrategy.registerCertificate(
        CSCACertBytes,
        eDocument.sod.slaveCertificate,
        slaveMaster
      );
    }

    const circuit = new NoirEPassportBasedRegistrationCircuit(eDocument);

    const registrationProof = await circuit.prove({
      skIdentity: BigInt(`0x${privateKey}`),
      icaoRoot: BigInt(slaveCertSmtProof.root),
      inclusionBranches: slaveCertSmtProof.siblings.map((el) => BigInt(el)),
    });

    const identityItem = new NoirEpassportIdentity(
      eDocument,
      registrationProof
    );

    const passportInfo = await identityItem.getPassportInfo();

    const currentIdentityKey = publicKeyHash;
    const currentIdentityKeyHex = hexlify(currentIdentityKey);

    const isPassportNotRegistered =
      !passportInfo ||
      passportInfo.passportInfo_.activeIdentity ===
        RegistrationStrategy.ZERO_BYTES32_HEX;

    const isPassportRegisteredWithCurrentPK =
      passportInfo?.passportInfo_.activeIdentity === currentIdentityKeyHex;

    if (isPassportNotRegistered) {
      const registerCallData = await this.buildRegisterCallData(
        identityItem,
        slaveCertSmtProof,
        false
      );

      await RegistrationStrategy.requestRelayerRegisterMethod(registerCallData);
    }

    if (!isPassportRegisteredWithCurrentPK) {
      throw new PassportRegisteredWithAnotherPKError();
    }

    return identityItem;
  };
}
