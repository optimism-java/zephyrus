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

/// Calculates the committee count per slot for a given epoch
/// Returns: The number of committees per slot
/// Spec pseudocode definition:
/// def get_committee_count_per_slot(state: BeaconState, epoch: Epoch) -> uint64:
///     """
///     Return the number of committees in each slot for the given ``epoch``.
///     """
///     return max(uint64(1), min(
///         MAX_COMMITTEES_PER_SLOT,
///         uint64(len(get_active_validator_indices(state, epoch))) // SLOTS_PER_EPOCH // TARGET_COMMITTEE_SIZE,
///     ))
pub fn getCommitteeCountPerSlot(state: *const consensus.BeaconState, epoch: primitives.Epoch, allocator: std.mem.Allocator) !u64 {
    const active_validator_indices = try validator_helper.getActiveValidatorIndices(state, epoch, allocator);
    defer allocator.free(active_validator_indices);

    const active_validator_count = active_validator_indices.len;
    std.debug.print("active_validator_count: {}\n", .{active_validator_count});
    const slots_per_epoch = preset.ActivePreset.get().SLOTS_PER_EPOCH;
    const target_committee_size = preset.ActivePreset.get().TARGET_COMMITTEE_SIZE;

    const committees_per_slot = @divFloor(active_validator_count, slots_per_epoch * target_committee_size);

    return @max(@as(u64, 1), @min(preset.ActivePreset.get().MAX_COMMITTEES_PER_SLOT, committees_per_slot));
}

test "test getCommitteeCountPerSlot" {
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

    const count = try getCommitteeCountPerSlot(&state, @as(primitives.Epoch, 5), std.testing.allocator);
    try std.testing.expectEqual(
        4,
        count,
    );
}
