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

// pub fn isValidDepositSignature(pubkey: primitives.BLSPubkey, withdrawal_credentials: primitives.Bytes32, amount: u64, signature: primitives.BLSSignature, allocator: std.mem.Allocator) bool {
//     const deposit_message = consensus.DepositMessage{
//         .pubkey = pubkey,
//         .withdrawal_credentials = withdrawal_credentials,
//         .amount = amount,
//     };
//     const domain = domain_helper.computeDomain(constants.DOMAIN_DEPOSIT, null, null, allocator); // Fork-agnostic domain since deposits are valid across forks
//     const signing_root = signing_root_helper.computeSigningRoot(deposit_message, domain, allocator);
//     return bls.verify(pubkey, signing_root, signature);
// }
