const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const shuffle_helper = @import("../../consensus/helpers/shuffle.zig");

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
/// Note: Caller is responsible for freeing the returned slice.
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

/// computeProposerIndex returns the index of the proposer for the current epoch.
/// @param state - The beacon state.
/// @param indices - The validator indices.
/// @param seed - The seed.
/// @returns The index of the proposer for the current epoch.
/// Spec pseudocode definition:
/// def compute_proposer_index(state: BeaconState, indices: Sequence[ValidatorIndex], seed: Bytes32) -> ValidatorIndex:
///     """
///     Return from ``indices`` a random index sampled by effective balance.
///    """
///    assert len(indices) > 0
///    MAX_RANDOM_BYTE = 2**8 - 1
///    i = uint64(0)
///    total = uint64(len(indices))
///    while True:
///       candidate_index = indices[compute_shuffled_index(i % total, total, seed)]
///       random_byte = hash(seed + uint_to_bytes(uint64(i // 32)))[i % 32]
///       effective_balance = state.validators[candidate_index].effective_balance
///       # [Modified in Electra:EIP7251]
///      if effective_balance * MAX_RANDOM_BYTE >= MAX_EFFECTIVE_BALANCE_ELECTRA * random_byte:
///          return candidate_index
///      i += 1
pub fn computeProposerIndex(state: *const consensus.BeaconState, indices: []const primitives.ValidatorIndex, seed: primitives.Bytes32) !primitives.ValidatorIndex {
    if (indices.len == 0) return error.EmptyValidatorIndices;
    const MAX_RANDOM_BYTE: u8 = std.math.maxInt(u8);
    var i: u64 = 0;
    const total: u64 = indices.len;

    while (true) {
        const shuffled_index = try shuffle_helper.computeShuffledIndex(@mod(i, total), total, seed);
        const candidate_index = indices[@intCast(shuffled_index)];
        var hash_result: [32]u8 = undefined;
        var seed_plus: [40]u8 = undefined;
        @memcpy(seed_plus[0..32], &seed);
        std.mem.writeInt(u64, seed_plus[32..40], @divFloor(i, 32), .little);
        std.log.debug("seed_plus: {any}, i: {}\n", .{ seed_plus, i });
        std.crypto.hash.sha2.Sha256.hash(&seed_plus, &hash_result, .{});
        const randomByte = hash_result[@mod(i, 32)];
        const effectiveBalance = state.validators()[candidate_index].effective_balance;

        const max_effective_balance = switch (state.*) {
            .electra => preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE_ELECTRA,
            else => preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE,
        };
        if (effectiveBalance * MAX_RANDOM_BYTE >= max_effective_balance * randomByte) {
            return candidate_index;
        }
        i += 1;
    }
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

test "test computeProposerIndex" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    var finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };
    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();
    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 12312312312,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator1);
    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 232323232332,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator2);

    var randao_mixes = try std.ArrayList(primitives.Bytes32).initCapacity(std.testing.allocator, preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR);
    defer randao_mixes.deinit();
    for (0..preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR) |slot_index| {
        try randao_mixes.append(.{@as(u8, @intCast(slot_index))} ** 32);
    }

    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 100,
            .fork = undefined,
            .block_roots = undefined,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = validators.items,
            .balances = undefined,
            .randao_mixes = randao_mixes.items,
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

    const validator_index = [_]primitives.ValidatorIndex{ 0, 1 };
    const proposer_index = try computeProposerIndex(&state, &validator_index, .{1} ** 32);
    try std.testing.expectEqual(0, proposer_index);
}
