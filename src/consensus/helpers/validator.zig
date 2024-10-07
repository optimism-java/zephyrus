const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");

/// Check if a validator is active at a given epoch.
/// A validator is active if the current epoch is greater than or equal to the validator's activation epoch and less than the validator's exit epoch.
/// @param validator The validator to check.
/// @param epoch The epoch to check.
/// @return True if the validator is active, false otherwise.
/// Spec pseudocode definition:
///
/// def is_active_validator(validator: Validator, epoch: Epoch) -> bool:
/// """
/// Check if ``validator`` is active.
/// """
///    return validator.activation_epoch <= epoch < validator.exit_epoch
pub fn isActiveValidator(validator: *const consensus.Validator, epoch: primitives.Epoch) bool {
    return validator.activation_epoch <= epoch and epoch < validator.exit_epoch;
}

/// isEligibleForActivationQueue carries out the logic for IsEligibleForActivationQueue
/// @param validator The validator to check.
/// Spec pseudocode definition:
///
/// def is_eligible_for_activation_queue(validator: Validator) -> bool:
///   """
///   Check if ``validator`` is eligible to be placed into the activation queue.
///   """
///   return (
///       validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
///       and validator.effective_balance == MAX_EFFECTIVE_BALANCE
///   )
pub fn isEligibleForActivationQueue(validator: *const consensus.Validator) bool {
    return validator.activation_eligibility_epoch == constants.FAR_FUTURE_EPOCH and
        validator.effective_balance == preset.ActivePreset.get().MIN_ACTIVATION_BALANCE;
}

/// isEligibleForActivation checks if a validator is eligible for activation.
/// A validator is eligible for activation if it is not yet activated and its activation eligibility epoch is less than or equal to the finalized epoch.
/// @param validator The validator to check.
/// @param state The beacon state.
/// @return True if the validator is eligible for activation, false otherwise.
/// Spec pseudocode definition:
///
/// def is_eligible_for_activation(state: BeaconState, validator: Validator) -> bool:
///   """
///   Check if ``validator`` is eligible for activation.
///   """
///   return (
///       validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
///       and validator.activation_epoch == FAR_FUTURE_EPOCH
///   )
pub fn isEligibleForActivation(validator: *const consensus.Validator, state: *const consensus.BeaconState) bool {
    return
    // Placement in queue is finalized
    validator.activation_eligibility_epoch <= state.finalizedCheckpointEpoch() and
        // Has not yet been activated
        validator.activation_epoch == constants.FAR_FUTURE_EPOCH;
}

/// isSlashableValidator checks if a validator is slashable.
/// A validator is slashable if it is not yet slashed and is within the range of epochs where it can be withdrawn.
/// @param validator The validator to check.
/// @param epoch The epoch to check.
/// @return True if the validator is slashable, false otherwise.
/// Spec pseudocode definition:
///
/// def is_slashable_validator(validator: Validator, epoch: Epoch) -> bool:
///     """
///    Check if ``validator`` is slashable.
///    """
///    return not validator.slashed and validator.activation_epoch <= epoch < validator.withdrawable_epoch
pub fn isSlashableValidator(validator: *const consensus.Validator, epoch: primitives.Epoch) bool {
    return (!validator.slashed) and (validator.activation_epoch <= epoch and epoch < validator.withdrawable_epoch);
}

/// getActiveValidatorIndices returns the indices of active validators for the given epoch.
/// @param state The beacon state.
/// @param epoch The epoch for which to get the active validator indices.
/// @return The indices of active validators for the given epoch.
/// Spec pseudocode definition:
/// def get_active_validator_indices(state: BeaconState, epoch: Epoch) -> Sequence[ValidatorIndex]:
///     """
///     Return the sequence of active validator indices at ``epoch``.
///     """
///     return [ValidatorIndex(i) for i, v in enumerate(state.validators) if is_active_validator(v, epoch)]
pub fn getActiveValidatorIndices(state: *const consensus.BeaconState, epoch: primitives.Epoch, allocator: std.mem.Allocator) ![]const primitives.ValidatorIndex {
    var active_validators = std.ArrayList(primitives.ValidatorIndex).init(allocator);
    errdefer active_validators.deinit();

    for (state.validators(), 0..) |v, i| {
        if (isActiveValidator(&v, epoch)) {
            try active_validators.append(@as(primitives.Epoch, i));
        }
    }

    return active_validators.toOwnedSlice();
}

/// getValidatorChurnLimit returns the validator churn limit for the given state.
/// The churn limit is the maximum number of validators who can leave the validator set in one epoch.
/// @param state The beacon state.
/// @return The validator churn limit.
/// Spec pseudocode definition:
/// def get_validator_churn_limit(state: BeaconState) -> uint64:
/// """
/// Return the validator churn limit for the current epoch.
/// """
/// active_validator_indices = get_active_validator_indices(state, get_current_epoch(state))
/// return max(config.MIN_PER_EPOCH_CHURN_LIMIT, uint64(len(active_validator_indices)) // config.CHURN_LIMIT_QUOTIENT)
pub fn getValidatorChurnLimit(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !u64 {
    const active_validator_indices = try getActiveValidatorIndices(state, epoch_helper.getCurrentEpoch(state), allocator);
    defer allocator.free(active_validator_indices);
    const conf = configs.ActiveConfig.get();
    return @max(conf.MIN_PER_EPOCH_CHURN_LIMIT, @divFloor(@as(u64, active_validator_indices.len), conf.CHURN_LIMIT_QUOTIENT));
}

test "test getValidatorChurnLimit" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    configs.ActiveConfig.set(preset.Presets.minimal);
    defer configs.ActiveConfig.reset();
    var finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();

    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };

    // add 800 validators
    for (0..400) |_| {
        try validators.append(validator1);
        try validators.append(validator2);
    }

    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 0,
            .fork = undefined,
            .block_roots = undefined,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = validators.items,
            .balances = undefined,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const churn_limit = try getValidatorChurnLimit(&state, std.testing.allocator);
    try std.testing.expectEqual(churn_limit, 25);

    var validators1 = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators1.deinit();

    try validators1.append(validator1);
    try validators1.append(validator2);

    const state1 = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 0,
            .fork = undefined,
            .block_roots = undefined,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = validators1.items,
            .balances = undefined,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const churn_limit1 = try getValidatorChurnLimit(&state1, std.testing.allocator);
    try std.testing.expectEqual(churn_limit1, 2);
}

test "test isActiveValidator" {
    const validator = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 0,
    };
    const epoch: primitives.Epoch = 5;
    const result = isActiveValidator(&validator, epoch);
    try std.testing.expectEqual(result, true);
}

test "test isEligibleForActivationQueue" {
    preset.ActivePreset.set(preset.Presets.mainnet);
    defer preset.ActivePreset.reset();
    const validator = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = preset.ActivePreset.get().MIN_ACTIVATION_BALANCE,
        .slashed = false,
        .activation_eligibility_epoch = constants.FAR_FUTURE_EPOCH,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    const result = isEligibleForActivationQueue(&validator);
    try std.testing.expectEqual(result, true);
}

test "test isEligibleForActivation" {
    var finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    const state = consensus.BeaconState{
        .phase0 = phase0.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = undefined,
            .slot = 0,
            .fork = undefined,
            .block_roots = undefined,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = undefined,
            .balances = undefined,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
        },
    };

    const validator = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = constants.FAR_FUTURE_EPOCH,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };

    const result = isEligibleForActivation(&validator, &state);
    try std.testing.expectEqual(result, true);

    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 10,
        .activation_epoch = constants.FAR_FUTURE_EPOCH,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };

    const result2 = isEligibleForActivation(&validator2, &state);
    try std.testing.expectEqual(result2, false);
}

test "test isSlashableValidator" {
    preset.ActivePreset.set(preset.Presets.mainnet);
    defer preset.ActivePreset.reset();
    const validator = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };
    const epoch: primitives.Epoch = 5;
    const result = isSlashableValidator(&validator, epoch);
    try std.testing.expectEqual(result, true);

    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 5,
    };
    const epoch2: primitives.Epoch = 5;
    const result2 = isSlashableValidator(&validator2, epoch2);
    try std.testing.expectEqual(result2, false);
}

test "test_getActiveValidatorIndices_withTwoActiveValidators" {
    var finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();

    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };
    try validators.append(validator1);
    try validators.append(validator2);

    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 0,
            .fork = undefined,
            .block_roots = undefined,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = validators.items,
            .balances = undefined,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const indices = try getActiveValidatorIndices(&state, @as(primitives.Epoch, 5), std.testing.allocator);
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqual(indices.len, 2);
}
