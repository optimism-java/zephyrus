const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");

/// getBlockRootAtSlot returns the block root at the given slot.
/// @param state - The state.
/// @param slot - The slot.
/// @return The block root at the given slot.
/// error InvalidSlot if the slot is invalid.
/// Spec pseudocode definition:
/// def get_block_root_at_slot(state: BeaconState, slot: Slot) -> Root:
///     """
///     Return the block root at a recent ``slot``.
///     """
///     assert slot < state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
///     return state.block_roots[slot % SLOTS_PER_HISTORICAL_ROOT]
pub fn getBlockRootAtSlot(state: *const consensus.BeaconState, slot: primitives.Slot) !primitives.Root {
    if (slot >= state.slot() or state.slot() > slot + preset.ActivePreset.get().SLOTS_PER_HISTORICAL_ROOT) {
        return error.InvalidSlot;
    }
    return state.blockRoots()[@mod(slot, preset.ActivePreset.get().SLOTS_PER_HISTORICAL_ROOT)];
}

/// getBlockRoot returns the block root at the start of a recent `epoch`.
/// @param state - The state.
/// @param epoch - The epoch.
/// @return The block root at the start of a recent `epoch`.
/// error InvalidSlot if the slot is invalid.
/// Spec pseudocode definition:
/// def get_block_root(state: BeaconState, epoch: Epoch) -> Root:
///     """
///     Return the block root at the start of a recent ``epoch``.
///    """
///    return get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))
pub fn getBlockRoot(state: *const consensus.BeaconState, epoch: primitives.Epoch) !primitives.Root {
    // Return the block root at the start of a recent `epoch`.
    return getBlockRootAtSlot(state, epoch_helper.computeStartSlotAtEpoch(epoch));
}

test "test get_block_root_at_slot" {
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

    var block_roots = std.ArrayList(primitives.Root).init(std.testing.allocator);
    defer block_roots.deinit();
    const block_root1 = .{0} ** 32;
    const block_root2 = .{1} ** 32;
    const block_root3 = .{2} ** 32;
    try block_roots.append(block_root1);
    try block_roots.append(block_root2);
    try block_roots.append(block_root3);
    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 100,
            .fork = undefined,
            .block_roots = block_roots.items,
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

    try std.testing.expectError(error.InvalidSlot, getBlockRootAtSlot(&state, 0));

    const state1 = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 70,
            .fork = undefined,
            .block_roots = block_roots.items,
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

    const block_root2_res = try getBlockRootAtSlot(&state1, 65);
    try std.testing.expectEqual(block_root2_res, block_root2);
}

test "test get_block_root" {
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

    var block_roots = try std.ArrayList(primitives.Root).initCapacity(std.testing.allocator, preset.ActivePreset.get().SLOTS_PER_HISTORICAL_ROOT);
    defer block_roots.deinit();
    for (0..preset.ActivePreset.get().SLOTS_PER_HISTORICAL_ROOT) |slot_index| {
        try block_roots.append(.{@as(u8, @intCast(slot_index))} ** 32);
    }
    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 100,
            .fork = undefined,
            .block_roots = block_roots.items,
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
    const block_root_res = try getBlockRoot(&state, 9);
    try std.testing.expectEqual(block_root_res, .{8} ** 32);
}
