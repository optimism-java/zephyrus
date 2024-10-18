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
const balance_helper = @import("../../consensus/helpers/balance.zig");
const committee_helper = @import("../../consensus/helpers/committee.zig");

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

/// getBalanceChurnLimit returns the balance churn limit for the current epoch.
/// The churn limit is the maximum number of validators who can leave the validator set in one epoch.
/// @param state The beacon state.
/// @param allocator The allocator.
/// @return The balance churn limit.
/// Spec pseudocode definition:
/// def get_balance_churn_limit(state: BeaconState) -> Gwei:
///     """
///     Return the churn limit for the current epoch.
///     """
///     churn = max(
///         config.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
///         get_total_active_balance(state) // config.CHURN_LIMIT_QUOTIENT
///     )
///     return churn - churn % EFFECTIVE_BALANCE_INCREMENT
pub fn getBalanceChurnLimit(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !primitives.Gwei {
    // Return the churn limit for the current epoch.
    const total_active_balance = try balance_helper.getTotalActiveBalance(state, allocator);
    const churn = @max(configs.ActiveConfig.get().MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, @divFloor(total_active_balance, configs.ActiveConfig.get().CHURN_LIMIT_QUOTIENT));
    return churn - @mod(churn, preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT);
}

/// initiateValidatorExitBellatrix sets the exit epoch and withdrawable epoch for a validator.
/// @param state The beacon state.
/// @param index The validator index.
/// @param allocator The allocator.
/// @return An error if the validator is already initiated exit.
/// Spec pseudocode definition:
/// def initiate_validator_exit(state: BeaconState, index: ValidatorIndex) -> None:
///     """
///     Initiate the exit of the validator with index ``index``.
///     """
///     # Return if validator already initiated exit
///     validator = state.validators[index]
///     if validator.exit_epoch != FAR_FUTURE_EPOCH:
///         return
///
///    # Compute exit queue epoch
///    exit_epochs = [v.exit_epoch for v in state.validators if v.exit_epoch != FAR_FUTURE_EPOCH]
///    exit_queue_epoch = max(exit_epochs + [compute_activation_exit_epoch(get_current_epoch(state))])
///    exit_queue_churn = len([v for v in state.validators if v.exit_epoch == exit_queue_epoch])
///    if exit_queue_churn >= get_validator_churn_limit(state):
///        exit_queue_epoch += Epoch(1)
///
///    # Set validator exit epoch and withdrawable epoch
///    validator.exit_epoch = exit_queue_epoch
///    validator.withdrawable_epoch = Epoch(validator.exit_epoch + config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
fn initiateValidatorExitBellatrix(state: *const consensus.BeaconState, index: primitives.ValidatorIndex, allocator: std.mem.Allocator) !void {
    // Return if validator already initiated exit
    var validator = &state.validators()[index];
    if (validator.exit_epoch != constants.FAR_FUTURE_EPOCH) {
        return;
    }

    // Compute exit queue epoch
    var exit_epochs = std.ArrayList(primitives.Epoch).init(allocator);
    defer exit_epochs.deinit();

    for (state.validators()) |v| {
        if (v.exit_epoch != constants.FAR_FUTURE_EPOCH) {
            try exit_epochs.append(v.exit_epoch);
        }
    }

    var exit_queue_epoch = @max(std.mem.max(primitives.Epoch, exit_epochs.items), epoch_helper.computeActivationExitEpoch(epoch_helper.getCurrentEpoch(state)));

    var exit_queue_churn: usize = 0;
    for (state.validators()) |v| {
        if (v.exit_epoch == exit_queue_epoch) {
            exit_queue_churn += 1;
        }
    }

    if (exit_queue_churn >= try getValidatorChurnLimit(state, allocator)) {
        exit_queue_epoch += 1;
    }

    // Set validator exit epoch and withdrawable epoch
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch = exit_queue_epoch + configs.ActiveConfig.get().MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
}

/// initiateValidatorExitElectra sets the exit epoch and withdrawable epoch for a validator.
/// @param state The beacon state.
/// @param index The validator index.
/// @param allocator The allocator.
/// @return An error if the validator is already initiated exit.
/// Spec pseudocode definition:
/// def initiate_validator_exit(state: BeaconState, index: ValidatorIndex) -> None:
///     """
///     Initiate the exit of the validator with index ``index``.
///     """
///     # Return if validator already initiated exit
///     validator = state.validators[index]
///     if validator.exit_epoch != FAR_FUTURE_EPOCH:
///         return
///
///     # Compute exit queue epoch [Modified in Electra:EIP7251]
///     exit_queue_epoch = compute_exit_epoch_and_update_churn(state, validator.effective_balance)
///
///     # Set validator exit epoch and withdrawable epoch
///     validator.exit_epoch = exit_queue_epoch
///     validator.withdrawable_epoch = Epoch(validator.exit_epoch + config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
fn initiateValidatorExitElectra(state: *consensus.BeaconState, index: primitives.ValidatorIndex, allocator: std.mem.Allocator) !void {
    // Return if validator already initiated exit
    var validator = &state.validators()[index];
    if (validator.exit_epoch != constants.FAR_FUTURE_EPOCH) {
        return;
    }

    // Compute exit queue epoch [Modified in Electra:EIP7251]
    const exit_queue_epoch = try epoch_helper.computeExitEpochAndUpdateChurn(state, validator.effective_balance, allocator);

    // Set validator exit epoch and withdrawable epoch
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch = exit_queue_epoch + configs.ActiveConfig.get().MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
}

/// initiateValidatorExit sets the exit epoch and withdrawable epoch for a validator.
/// @param state The beacon state.
/// @param index The index of the validator.
/// @param allocator The allocator.
/// @return An error if the validator is already initiated exit.
/// Spec pseudocode definition:
/// See `initiateValidatorExitElectra` and `initiateValidatorExitBellatrix` for the Bellatrix and Electra implementations.
pub fn initiateValidatorExit(state: *consensus.BeaconState, index: primitives.ValidatorIndex, allocator: std.mem.Allocator) !void {
    switch (state.*) {
        .electra => try initiateValidatorExitElectra(state, index, allocator),
        else => try initiateValidatorExitBellatrix(state, index, allocator),
    }
}

/// slashValidator slashes a validator and applies the penalty to the state.
/// @param state The beacon state.
/// @param slashed_index The index of the validator to slash.
/// @param whistleblower_index The index of the whistleblower.
/// @param allocator The allocator.
/// Spec pseudocode definition:
/// def slash_validator(state: BeaconState,
///                     slashed_index: ValidatorIndex,
///                     whistleblower_index: ValidatorIndex=None) -> None:
///     """
///     Slash the validator with index ``slashed_index``.
///     """
///     epoch = get_current_epoch(state)
///     initiate_validator_exit(state, slashed_index)
///     validator = state.validators[slashed_index]
///     validator.slashed = True
///     validator.withdrawable_epoch = max(validator.withdrawable_epoch, Epoch(epoch + EPOCHS_PER_SLASHINGS_VECTOR))
///     state.slashings[epoch % EPOCHS_PER_SLASHINGS_VECTOR] += validator.effective_balance
///     # [Modified in Electra:EIP7251]
///     slashing_penalty = validator.effective_balance // MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA
///     decrease_balance(state, slashed_index, slashing_penalty)
///
///     # Apply proposer and whistleblower rewards
///     proposer_index = get_beacon_proposer_index(state)
///     if whistleblower_index is None:
///          whistleblower_index = proposer_index
///     whistleblower_reward = Gwei(
///          validator.effective_balance // WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA)  # [Modified in Electra:EIP7251]
///     proposer_reward = Gwei(whistleblower_reward * PROPOSER_WEIGHT // WEIGHT_DENOMINATOR)
///     increase_balance(state, proposer_index, proposer_reward)
///     increase_balance(state, whistleblower_index, Gwei(whistleblower_reward - proposer_reward))
pub fn slashValidator(state: *consensus.BeaconState, slashed_index: primitives.ValidatorIndex, whistleblower_index: ?primitives.ValidatorIndex, allocator: std.mem.Allocator) !void {
    const epoch = epoch_helper.getCurrentEpoch(state);
    try initiateValidatorExit(state, slashed_index, allocator);
    var validator = &state.validators()[slashed_index];
    validator.slashed = true;
    validator.withdrawable_epoch = @max(validator.withdrawable_epoch, epoch + preset.ActivePreset.get().EPOCHS_PER_SLASHINGS_VECTOR);
    state.slashings()[try std.math.mod(primitives.Epoch, epoch, preset.ActivePreset.get().EPOCHS_PER_SLASHINGS_VECTOR)] += validator.effective_balance;
    const InternalConfig = struct {
        min_slashing_penalty_quotient: u64,
        whistleblower_reward_quotient: u64,
        is_phase0: bool,
    };

    const config = switch (state.*) {
        .phase0 => InternalConfig{
            .min_slashing_penalty_quotient = preset.ActivePreset.get().MIN_SLASHING_PENALTY_QUOTIENT,
            .whistleblower_reward_quotient = preset.ActivePreset.get().WHISTLEBLOWER_REWARD_QUOTIENT,
            .is_phase0 = true,
        },
        .altair => InternalConfig{
            .min_slashing_penalty_quotient = preset.ActivePreset.get().MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
            .whistleblower_reward_quotient = preset.ActivePreset.get().WHISTLEBLOWER_REWARD_QUOTIENT,
            .is_phase0 = false,
        },
        .bellatrix, .capella, .deneb => InternalConfig{
            .min_slashing_penalty_quotient = preset.ActivePreset.get().MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
            .whistleblower_reward_quotient = preset.ActivePreset.get().WHISTLEBLOWER_REWARD_QUOTIENT,
            .is_phase0 = false,
        },
        .electra => InternalConfig{
            .min_slashing_penalty_quotient = preset.ActivePreset.get().MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
            .whistleblower_reward_quotient = preset.ActivePreset.get().WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
            .is_phase0 = false,
        },
    };

    balance_helper.decreaseBalance(state, slashed_index, try std.math.divFloor(primitives.Gwei, validator.effective_balance, config.min_slashing_penalty_quotient));

    // Apply proposer and whistleblower rewards
    const proposer_index = try committee_helper.getBeaconProposerIndex(state, allocator);
    const whistleblower = whistleblower_index orelse proposer_index;
    const whistleblower_reward = try std.math.divFloor(primitives.Gwei, validator.effective_balance, config.whistleblower_reward_quotient);
    const proposer_reward = if (config.is_phase0)
        try std.math.divFloor(primitives.Gwei, whistleblower_reward, preset.ActivePreset.get().PROPOSER_REWARD_QUOTIENT)
    else
        try std.math.divFloor(primitives.Gwei, whistleblower_reward * constants.PROPOSER_WEIGHT, constants.WEIGHT_DENOMINATOR);
    balance_helper.increaseBalance(state, proposer_index, proposer_reward);
    balance_helper.increaseBalance(state, whistleblower, whistleblower_reward - proposer_reward);
}

test "test getBalanceChurnLimit" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    configs.ActiveConfig.set(preset.Presets.minimal);
    defer configs.ActiveConfig.reset();
    const finalized_checkpoint = consensus.Checkpoint{
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
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const result = try getBalanceChurnLimit(&state, std.testing.allocator);
    try std.testing.expectEqual(@as(primitives.Gwei, 64000000000), result);
}

test "test getValidatorChurnLimit" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    configs.ActiveConfig.set(preset.Presets.minimal);
    defer configs.ActiveConfig.reset();
    const finalized_checkpoint = consensus.Checkpoint{
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
            .finalized_checkpoint = finalized_checkpoint,
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
            .finalized_checkpoint = finalized_checkpoint,
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
    const finalized_checkpoint = consensus.Checkpoint{
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
            .finalized_checkpoint = finalized_checkpoint,
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
    const finalized_checkpoint = consensus.Checkpoint{
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
            .finalized_checkpoint = finalized_checkpoint,
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
    const finalized_checkpoint = consensus.Checkpoint{
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
            .finalized_checkpoint = finalized_checkpoint,
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

test "test slashValidator" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();

    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 100000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 100000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };
    try validators.append(validator1);
    try validators.append(validator2);

    var slashings = [_]primitives.Gwei{1000000000000000} ** 4;
    var balances = [_]primitives.Gwei{10000000000000000000} ** 4;

    var randao_mixes = try std.ArrayList(primitives.Bytes32).initCapacity(std.testing.allocator, preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR);
    defer randao_mixes.deinit();
    for (0..preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR) |slot_index| {
        try randao_mixes.append(.{@as(u8, @intCast(slot_index))} ** 32);
    }
    var state = consensus.BeaconState{
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
            .balances = &balances,
            .randao_mixes = randao_mixes.items,
            .slashings = &slashings,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    try slashValidator(&state, 0, 1, std.testing.allocator);
    try std.testing.expectEqual(true, state.altair.validators[0].slashed);
    try std.testing.expectEqual(false, state.altair.validators[1].slashed);
    try std.testing.expectEqual(64, state.altair.validators[0].withdrawable_epoch);
    try std.testing.expectEqual(20, state.altair.validators[1].withdrawable_epoch);
    try std.testing.expectEqual(10, state.altair.validators[0].exit_epoch);
    try std.testing.expectEqual(20, state.altair.validators[1].exit_epoch);
}
