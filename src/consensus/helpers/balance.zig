const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");

/// getTotalBalance returns the sum of the effective balances in Gwei of the validators with indices in ``indices``.
/// @param state - The state.
/// @param indices - The indices of the validators to sum the effective balances of.
/// @returns The sum of the effective balances in Gwei of the validators with indices in ``indices``.
/// Spec pseudocode definition:
/// def get_total_balance(state: BeaconState, indices: Set[ValidatorIndex]) -> Gwei:
///     """
///     Return the combined effective balance of the ``indices``.
///    ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
///     Math safe up to ~10B ETH, after which this overflows uint64.
///    """
///    return Gwei(max(EFFECTIVE_BALANCE_INCREMENT, sum([state.validators[index].effective_balance for index in indices])))
pub fn getTotalBalance(state: *const consensus.BeaconState, indices: *const std.AutoHashMap(primitives.ValidatorIndex, void)) primitives.Gwei {
    var total: primitives.Gwei = 0;
    var iterator = indices.keyIterator();
    while (iterator.next()) |index| {
        std.log.debug("index: {}\n", .{index});
        std.log.debug("state.validators()[index.*].effective_balance: {}\n", .{state.validators()[index.*].effective_balance});
        total += state.validators()[index.*].effective_balance;
    }
    return @max(preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT, total);
}

/// getTotalActiveBalance returns the sum of the effective balances in Gwei of the active validators in the beacon state.
/// @param state - The state.
/// @param allocator - The allocator to use.
/// @returns The sum of the effective balances in Gwei of the active validators in the beacon state.
/// Spec pseudocode definition:
/// def get_total_active_balance(state: BeaconState) -> Gwei:
///     """
///     Return the combined effective balance of the active validators.
///     Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
///     """
///    return get_total_balance(state, set(get_active_validator_indices(state, get_current_epoch(state))))
pub fn getTotalActiveBalance(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !primitives.Gwei {
    const active_indices = try validator_helper.getActiveValidatorIndices(state, epoch_helper.getCurrentEpoch(state), allocator);
    defer allocator.free(active_indices);
    var indices_set = std.AutoHashMap(primitives.ValidatorIndex, void).init(allocator);
    defer indices_set.deinit();

    for (active_indices) |index| {
        try indices_set.put(index, {});
    }

    return getTotalBalance(state, &indices_set);
}

/// increaseBalance increases the validator balance at index `index` by `delta`.
/// @param state - The state.
/// @param index - The index of the validator to increase the balance of.
/// @param delta - The amount to increase the balance by.
/// Spec pseudocode definition:
/// def increase_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> None:
///     """
///     Increase the validator balance at index ``index`` by ``delta``.
///     """
///     state.balances[index] += delta
pub fn increaseBalance(state: *const consensus.BeaconState, index: primitives.ValidatorIndex, delta: primitives.Gwei) void {
    // Increase the validator balance at index `index` by `delta`.
    state.balances()[index] += delta;
}

/// decreaseBalance decreases the validator balance at index `index` by `delta`.
/// @param state - The state.
/// @param index - The index of the validator to decrease the balance of.
/// @param delta - The amount to decrease the balance by.
/// Spec pseudocode definition:
/// def decrease_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> None:
///     """
///     Decrease the validator balance at index ``index`` by ``delta``, with underflow protection.
///     """
///     state.balances[index] = 0 if delta > state.balances[index] else state.balances[index] - delta
pub fn decreaseBalance(state: *const consensus.BeaconState, index: primitives.ValidatorIndex, delta: primitives.Gwei) void {
    if (delta > state.balances()[index]) {
        state.balances()[index] = 0;
    } else {
        state.balances()[index] -= delta;
    }
}

/// getMaxEffectiveBalance returns the maximum effective balance for `validator`.
/// @param validator - The validator to get the maximum effective balance for.
/// @returns The maximum effective balance for `validator`.
/// Spec pseudocode definition:
/// def get_max_effective_balance(validator: Validator) -> Gwei:
///     """
///     Get max effective balance for ``validator``.
///     """
///     if has_compounding_withdrawal_credential(validator):
///        return MAX_EFFECTIVE_BALANCE_ELECTRA
///     else:
///        return MIN_ACTIVATION_BALANCE
pub fn getMaxEffectiveBalance(validator: *const consensus.Validator) primitives.Gwei {
    // Get max effective balance for `validator`.
    if (validator_helper.hasCompoundingWithdrawalCredential(validator)) {
        return preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE_ELECTRA;
    } else {
        return preset.ActivePreset.get().MIN_ACTIVATION_BALANCE;
    }
}

test "test getTotalBalance" {
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
        .effective_balance = 10000000000,
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

    for (0..500000) |_| {
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
            .previous_epoch_participation = undefined,
            .current_epoch_participation = undefined,
        },
    };

    const indices = [_]primitives.ValidatorIndex{ 0, 1, 500001, 500002 };
    var indices_map = std.AutoHashMap(primitives.ValidatorIndex, void).init(std.testing.allocator);
    defer indices_map.deinit();
    for (indices) |index| {
        indices_map.put(index, {}) catch unreachable;
    }
    const total = getTotalBalance(&state, &indices_map);
    try std.testing.expectEqual(
        220000000000,
        total,
    );
}

test "test getTotalActiveBalance" {
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
        .effective_balance = 10000000000,
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

    for (0..500000) |_| {
        try validators.append(validator1);
        try validators.append(validator2);
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
            .previous_epoch_participation = undefined,
            .current_epoch_participation = undefined,
        },
    };

    const total = getTotalActiveBalance(&state, std.testing.allocator);
    try std.testing.expectEqual(
        50000000000000000,
        total,
    );
}

test "test increaseBalance" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();

    var balances = [_]primitives.Gwei{ 0, 10000000000, 100000000000, 1000000000000 };
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
            .validators = undefined,
            .balances = &balances,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = undefined,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
            .previous_epoch_participation = undefined,
            .current_epoch_participation = undefined,
        },
    };

    increaseBalance(&state, 2, 10000000000);
    try std.testing.expectEqual(
        110000000000,
        state.balances()[2],
    );
}

test "test decreaseBalance" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();

    var balances = [_]primitives.Gwei{ 0, 10000000000, 100000000000, 1000000000000 };
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
            .validators = undefined,
            .balances = &balances,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = undefined,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
            .previous_epoch_participation = undefined,
            .current_epoch_participation = undefined,
        },
    };

    decreaseBalance(&state, 2, 10000000000);
    try std.testing.expectEqual(
        90000000000,
        state.balances()[2],
    );

    decreaseBalance(&state, 2, 100000000000);
    try std.testing.expectEqual(
        0,
        state.balances()[2],
    );
}

test "test getMaxEffectiveBalance" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();

    const validator = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = [_]u8{0x2} ++ [_]u8{0} ** 31,
        .effective_balance = 10000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const max_effective_balance = getMaxEffectiveBalance(&validator);
    try std.testing.expectEqual(
        preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE_ELECTRA,
        max_effective_balance,
    );

    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = [_]u8{0} ** 32,
        .effective_balance = 10000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const max_effective_balance1 = getMaxEffectiveBalance(&validator1);
    try std.testing.expectEqual(
        preset.ActivePreset.get().MIN_ACTIVATION_BALANCE,
        max_effective_balance1,
    );
}
