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
pub fn getTotalBalance(state: *const consensus.BeaconState, indices: std.AutoHashMap(primitives.ValidatorIndex, void)) primitives.Gwei {
    var total: primitives.Gwei = 0;
    var iterator = indices.keyIterator();
    while (iterator.next()) |index| {
        std.debug.print("index: {}\n", .{index});
        std.debug.print("state.validators()[index.*].effective_balance: {}\n", .{state.validators()[index.*].effective_balance});
        total += state.validators()[index.*].effective_balance;
    }
    return @max(preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT, total);
}

test "test getTotalBalance" {
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
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const indices = [_]primitives.ValidatorIndex{ 0, 1, 500001, 500002 };
    var indices_map = std.AutoHashMap(primitives.ValidatorIndex, void).init(std.testing.allocator);
    defer indices_map.deinit();
    for (indices) |index| {
        indices_map.put(index, {}) catch unreachable;
    }
    const total = getTotalBalance(&state, indices_map);
    try std.testing.expectEqual(
        220000000000,
        total,
    );
}
