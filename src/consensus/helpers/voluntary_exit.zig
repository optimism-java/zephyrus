const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const electra = @import("../../consensus/electra/types.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const domain_helper = @import("../../consensus/helpers/domain.zig");
const signing_root_helper = @import("../../consensus/helpers/signing_root.zig");
const bls_helper = @import("../../consensus/helpers/bls.zig");

/// processVoluntaryExit processes a voluntary exit.
///
/// Spec pseudocode definition:
/// def process_voluntary_exit(state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit) -> None:
///     voluntary_exit = signed_voluntary_exit.message
///     validator = state.validators[voluntary_exit.validator_index]
///     # Verify the validator is active
///     assert is_active_validator(validator, get_current_epoch(state))
///     # Verify exit has not been initiated
///     assert validator.exit_epoch == FAR_FUTURE_EPOCH
///     # Exits must specify an epoch when they become valid; they are not valid before then
///     assert get_current_epoch(state) >= voluntary_exit.epoch
///     # Verify the validator has been active long enough
///     assert get_current_epoch(state) >= validator.activation_epoch + config.SHARD_COMMITTEE_PERIOD
///     # Verify signature
///     # [Modified in Deneb:EIP7044]
///     domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, config.CAPELLA_FORK_VERSION, state.genesis_validators_root)
///     signing_root = compute_signing_root(voluntary_exit, domain)
///     assert bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)
///     # Initiate exit
///     initiate_validator_exit(state, voluntary_exit.validator_index)
pub fn processVoluntaryExit(state: *consensus.BeaconState, signed_voluntary_exit: *const consensus.SignedVoluntaryExit, allocator: std.mem.Allocator) !void {
    const voluntary_exit = signed_voluntary_exit.message;
    const validator = state.validators()[voluntary_exit.validator_index];

    const current_epoch = epoch_helper.getCurrentEpoch(state);

    // Verify the validator is active
    if (!validator_helper.isActiveValidator(&validator, current_epoch)) {
        return error.ValidatorNotActive;
    }

    // Verify exit has not been initiated
    if (validator.exit_epoch != constants.FAR_FUTURE_EPOCH) {
        return error.ValidatorExitInitiated;
    }

    // Exits must specify an epoch when they become valid; they are not valid before then
    if (current_epoch < voluntary_exit.epoch) {
        return error.ExitTooEarly;
    }

    // Verify the validator has been active long enough
    if (current_epoch < validator.activation_epoch + configs.ActiveConfig.get().SHARD_COMMITTEE_PERIOD) {
        return error.ValidatorTooYoung;
    }

    const state_enum = @intFromEnum(state.*);
    const is_electra_or_later = state_enum >= @intFromEnum(primitives.ForkType.electra);
    const is_deneb_or_later = state_enum >= @intFromEnum(primitives.ForkType.deneb);

    if (is_electra_or_later) {
        // Only exit validator if it has no pending withdrawals in the queue
        const pending_balance = validator_helper.getPendingBalanceToWithdraw(state, voluntary_exit.validator_index);
        if (pending_balance != 0) {
            return error.ValidatorHasBalance;
        }
    }

    const fork_version = if (is_deneb_or_later)
        configs.ActiveConfig.get().CAPELLA_FORK_VERSION
    else
        null;

    // Verify signature
    const domain = try domain_helper.computeDomain(constants.DOMAIN_VOLUNTARY_EXIT, fork_version, state.genesisValidatorsRoot(), allocator);
    const signing_root = try signing_root_helper.computeSigningRoot(&voluntary_exit, &domain, allocator);
    if (!bls_helper.verify(&validator.pubkey, &signing_root, &signed_voluntary_exit.signature)) {
        return error.InvalidSignature;
    }

    // Initiate exit
    try validator_helper.initiateValidatorExit(state, voluntary_exit.validator_index, allocator);
}
