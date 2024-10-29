const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const domain_helper = @import("../../consensus/helpers/domain.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");
const signing_root_helper = @import("../../consensus/helpers/signing_root.zig");
const bls_helper = @import("../../consensus/helpers/bls.zig");
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
