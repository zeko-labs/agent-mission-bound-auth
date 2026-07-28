import {
  Field,
  Permissions,
  PublicKey,
  SmartContract,
  State,
  Struct,
  UInt64,
  method,
  state
} from "o1js";

/**
 * Frozen v0 contract retained for source and deployed-contract compatibility.
 * New trustless settlement deployments use MissionRegistry.
 */
export class PrivateComputeReceipt extends Struct({
  authCommitment: Field,
  datasetCommitment: Field,
  policyHash: Field,
  outputHash: Field,
  paymentContextDigest: Field,
  amountNanomina: UInt64,
  payer: PublicKey,
  beneficiary: PublicKey
}) {}

export class PrivateComputeAccess extends SmartContract {
  @state(Field) datasetRoot = State<Field>();
  @state(Field) authRoot = State<Field>();
  @state(Field) receiptRoot = State<Field>();
  @state(PublicKey) beneficiary = State<PublicKey>();

  init() {
    super.init();
    this.datasetRoot.set(Field(0));
    this.authRoot.set(Field(0));
    this.receiptRoot.set(Field(0));
    this.beneficiary.set(PublicKey.empty());
    this.account.permissions.set({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
      setPermissions: Permissions.signature()
    });
  }

  @method async configureBeneficiary(beneficiary: PublicKey) {
    this.requireSignature();
    const currentBeneficiary = this.beneficiary.getAndRequireEquals();
    currentBeneficiary.isEmpty().assertTrue("beneficiary_already_configured");
    beneficiary.isEmpty().assertFalse("beneficiary_required");
    this.beneficiary.set(beneficiary);
  }

  @method async registerDatasetCommitment(
    previousRoot: Field,
    nextRoot: Field
  ) {
    const currentRoot = this.datasetRoot.getAndRequireEquals();
    currentRoot.assertEquals(previousRoot);
    this.datasetRoot.set(nextRoot);
  }

  @method async registerAuthCommitment(
    previousRoot: Field,
    nextRoot: Field
  ) {
    const currentRoot = this.authRoot.getAndRequireEquals();
    currentRoot.assertEquals(previousRoot);
    this.authRoot.set(nextRoot);
  }

  @method async recordPrivateComputeReceipt(
    previousRoot: Field,
    nextRoot: Field,
    receipt: PrivateComputeReceipt
  ) {
    const currentRoot = this.receiptRoot.getAndRequireEquals();
    currentRoot.assertEquals(previousRoot);

    const beneficiary = this.beneficiary.getAndRequireEquals();
    receipt.beneficiary.assertEquals(beneficiary);
    receipt.amountNanomina.assertGreaterThan(UInt64.from(0));

    this.receiptRoot.set(nextRoot);
  }
}
