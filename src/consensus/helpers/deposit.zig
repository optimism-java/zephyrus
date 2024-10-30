const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const electra = @import("../../consensus/electra/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const domain_helper = @import("../../consensus/helpers/domain.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");
const signing_root_helper = @import("../../consensus/helpers/signing_root.zig");
const bls_helper = @import("../../consensus/helpers/bls.zig");
const balance_helper = @import("../../consensus/helpers/balance.zig");
const merkle_helper = @import("../../consensus/helpers/merkle.zig");
const ssz = @import("../../ssz/ssz.zig");
const bls = @import("../../bls/bls.zig");

/// isValidDepositSignature verifies that the deposit signature is valid.
///
/// Spec pseudocode definition:
/// def is_valid_deposit_signature(pubkey: BLSPubkey,
///                                withdrawal_credentials: Bytes32,
///                                amount: uint64,
///                                signature: BLSSignature) -> bool:
///     deposit_message = DepositMessage(
///             pubkey=pubkey,
///             withdrawal_credentials=withdrawal_credentials,
///             amount=amount,
///     )
///     domain = compute_domain(DOMAIN_DEPOSIT)  # Fork-agnostic domain since deposits are valid across forks
///     signing_root = compute_signing_root(deposit_message, domain)
///     return bls.Verify(pubkey, signing_root, signature)
pub fn isValidDepositSignature(pubkey: *const primitives.BLSPubkey, withdrawal_credentials: *const primitives.Bytes32, amount: u64, signature: *const primitives.BLSSignature, allocator: std.mem.Allocator) !bool {
    const deposit_message = consensus.DepositMessage{
        .pubkey = pubkey.*,
        .withdrawal_credentials = withdrawal_credentials.*,
        .amount = amount,
    };
    const domain = try domain_helper.computeDomain(constants.DOMAIN_DEPOSIT, null, null, allocator); // Fork-agnostic domain since deposits are valid across forks
    const signing_root = try signing_root_helper.computeSigningRoot(&deposit_message, &domain, allocator);
    return bls_helper.verify(pubkey, &signing_root, signature);
}

/// applyDeposit applies a deposit to the state.
///
/// Spec pseudocode definition:
/// def apply_deposit(state: BeaconState,
///                   pubkey: BLSPubkey,
///                   withdrawal_credentials: Bytes32,
///                   amount: uint64,
///                   signature: BLSSignature) -> None:
///     validator_pubkeys = [v.pubkey for v in state.validators]
///     if pubkey not in validator_pubkeys:
///         # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
///         if is_valid_deposit_signature(pubkey, withdrawal_credentials, amount, signature):
///             add_validator_to_registry(state, pubkey, withdrawal_credentials, amount)
///     else:
///         # Increase balance by deposit amount
///         index = ValidatorIndex(validator_pubkeys.index(pubkey))
///         state.pending_balance_deposits.append(
///             PendingBalanceDeposit(index=index, amount=amount)
///         )  # [Modified in Electra:EIP7251]
///         # Check if valid deposit switch to compounding credentials
///         if (
///             is_compounding_withdrawal_credential(withdrawal_credentials)
///             and has_eth1_withdrawal_credential(state.validators[index])
///             and is_valid_deposit_signature(pubkey, withdrawal_credentials, amount, signature)
///         ):
///             switch_to_compounding_validator(state, index)
pub fn applyDeposit(
    state: *consensus.BeaconState,
    pubkey: *const primitives.BLSPubkey,
    withdrawal_credentials: *const primitives.Bytes32,
    amount: u64,
    signature: *const primitives.BLSSignature,
    allocator: std.mem.Allocator,
) !void {
    var index: isize = -1;
    for (state.validators(), 0..) |validator, i| {
        if (std.mem.eql(u8, &validator.pubkey, pubkey)) {
            index = @intCast(i);
            break;
        }
    }

    if (index == -1) {
        const is_valid = try isValidDepositSignature(pubkey, withdrawal_credentials, amount, signature, allocator);
        if (is_valid) {
            try validator_helper.addValidatorToRegistry(state, pubkey, withdrawal_credentials, amount);
        }
    } else {
        switch (state.*) {
            .electra => {
                state.pendingBalanceDeposit()[state.pendingBalanceDeposit().len] = consensus.PendingBalanceDeposit{
                    .electra = electra.PendingBalanceDeposit{
                        .index = @intCast(index),
                        .amount = amount,
                    },
                };

                if (validator_helper.isCompoundingWithdrawalCredential(withdrawal_credentials) and validator_helper.hasEth1WithdrawalCredential(&state.validators()[@intCast(index)]) and (try isValidDepositSignature(pubkey, withdrawal_credentials, amount, signature, allocator))) {
                    validator_helper.switchToCompoundingValidator(state, @intCast(index));
                }
            },
            inline else => {
                balance_helper.increaseBalance(state, @intCast(index), amount);
            },
        }
    }
}

/// processDeposit processes `deposit` by adding the deposited amount to the validator's balance.
///
/// Spec pseudocode definition:
/// def process_deposit(state: BeaconState, deposit: Deposit) -> None:
///     # Verify the Merkle branch
///     assert is_valid_merkle_branch(
///         leaf=hash_tree_root(deposit.data),
///         branch=deposit.proof,
///         depth=DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the List length mix-in
///         index=state.eth1_deposit_index,
///         root=state.eth1_data.deposit_root,
///     )
///
///     # Deposits must be processed in order
///     state.eth1_deposit_index += 1
///
///     apply_deposit(
///         state=state,
///         pubkey=deposit.data.pubkey,
///         withdrawal_credentials=deposit.data.withdrawal_credentials,
///         amount=deposit.data.amount,
///         signature=deposit.data.signature,
///     )
pub fn processDeposit(state: *consensus.BeaconState, deposit: *const consensus.Deposit, allocator: std.mem.Allocator) !void {
    // Verify the Merkle branch
    var data_root: primitives.Bytes32 = undefined;
    try ssz.hashTreeRoot(&deposit.data, &data_root, allocator);
    const is_valid = try merkle_helper.isValidMerkleBranch(&data_root, &deposit.proof, constants.DEPOSIT_CONTRACT_TREE_DEPTH + 1, state.eth1DepositIndex(), &state.eth1Data().deposit_root);
    if (!is_valid) {
        return error.InvalidDepositProof;
    }

    // Deposits must be processed in order
    state.setEth1DepositIndex(state.eth1DepositIndex() + 1);

    try applyDeposit(state, &deposit.data.pubkey, &deposit.data.withdrawal_credentials, deposit.data.amount, &deposit.data.signature, allocator);
}

test "test isvalidDepositSignature" {
    _ = bls.init();
    configs.ActiveConfig.set(preset.Presets.minimal);
    defer configs.ActiveConfig.reset();
    var sk: bls.SecretKey = undefined;
    var pk: bls.PublicKey = undefined;
    sk.setByCSPRNG();
    var sk_bytes: [32]u8 = undefined;
    var sk_bytes_slice: []u8 = &sk_bytes;
    _ = sk.serialize(&sk_bytes_slice);
    _ = sk.getPublicKey(&pk);
    var pk_bytes: primitives.BLSPubkey = undefined;
    var pk_bytes_slice: []u8 = &pk_bytes;
    _ = pk.serialize(&pk_bytes_slice);
    const deposit_message = consensus.DepositMessage{
        .pubkey = pk_bytes,
        .withdrawal_credentials = [_]u8{1} ** 32,
        .amount = 1000000000,
    };
    const domain = try domain_helper.computeDomain(constants.DOMAIN_DEPOSIT, null, null, std.testing.allocator); // Fork-agnostic domain since deposits are valid across forks
    const signing_root = try signing_root_helper.computeSigningRoot(&deposit_message, &domain, std.testing.allocator);
    var sig: bls.Signature = undefined;
    sk.sign(&sig, &signing_root);

    var sig_bytes: primitives.BLSSignature = undefined;
    var sig_bytes_slice: []u8 = &sig_bytes;
    _ = sig.serialize(&sig_bytes_slice);

    const res = try isValidDepositSignature(&pk_bytes, &deposit_message.withdrawal_credentials, deposit_message.amount, &sig_bytes, std.testing.allocator);
    try std.testing.expect(res);
}
