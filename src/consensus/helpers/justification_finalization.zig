const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const electra = @import("../../consensus/electra/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const shuffle_helper = @import("../../consensus/helpers/shuffle.zig");
const balance_helper = @import("../../consensus/helpers/balance.zig");
const committee_helper = @import("../../consensus/helpers/committee.zig");
const siging_root_helper = @import("../../consensus/helpers/signing_root.zig");
const block_root_helper = @import("../../consensus/helpers/block_root.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");

/// weighJustificationAndFinalization weighs justification and finalization for the current epoch.
///
/// Spec pseudocode definition:
/// def weigh_justification_and_finalization(state: BeaconState,
///                                          total_active_balance: Gwei,
///                                          previous_epoch_target_balance: Gwei,
///                                          current_epoch_target_balance: Gwei) -> None:
///     previous_epoch = get_previous_epoch(state)
///     current_epoch = get_current_epoch(state)
///     old_previous_justified_checkpoint = state.previous_justified_checkpoint
///     old_current_justified_checkpoint = state.current_justified_checkpoint
///
///     # Process justifications
///     state.previous_justified_checkpoint = state.current_justified_checkpoint
///     state.justification_bits[1:] = state.justification_bits[:JUSTIFICATION_BITS_LENGTH - 1]
///     state.justification_bits[0] = 0b0
///     if previous_epoch_target_balance * 3 >= total_active_balance * 2:
///         state.current_justified_checkpoint = Checkpoint(epoch=previous_epoch,
///                                                         root=get_block_root(state, previous_epoch))
///         state.justification_bits[1] = 0b1
///     if current_epoch_target_balance * 3 >= total_active_balance * 2:
///         state.current_justified_checkpoint = Checkpoint(epoch=current_epoch,
///                                                         root=get_block_root(state, current_epoch))
///         state.justification_bits[0] = 0b1
///
///     # Process finalizations
///     bits = state.justification_bits
///     # The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
///     if all(bits[1:4]) and old_previous_justified_checkpoint.epoch + 3 == current_epoch:
///         state.finalized_checkpoint = old_previous_justified_checkpoint
///     # The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
///     if all(bits[1:3]) and old_previous_justified_checkpoint.epoch + 2 == current_epoch:
///         state.finalized_checkpoint = old_previous_justified_checkpoint
///     # The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
///     if all(bits[0:3]) and old_current_justified_checkpoint.epoch + 2 == current_epoch:
///         state.finalized_checkpoint = old_current_justified_checkpoint
///     # The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
///     if all(bits[0:2]) and old_current_justified_checkpoint.epoch + 1 == current_epoch:
///         state.finalized_checkpoint = old_current_justified_checkpoint
pub fn weighJustificationAndFinalization(
    state: *consensus.BeaconState,
    total_active_balance: primitives.Gwei,
    previous_epoch_target_balance: primitives.Gwei,
    current_epoch_target_balance: primitives.Gwei,
) !void {
    const previous_epoch = epoch_helper.getPreviousEpoch(state);
    const current_epoch = epoch_helper.getCurrentEpoch(state);
    const old_previous_justified_checkpoint = state.previousJustifiedCheckpoint();
    const old_current_justified_checkpoint = state.currentJustifiedCheckpoint();

    // Process justifications
    state.setPreviousJustifiedCheckpoint(&state.currentJustifiedCheckpoint());

    // Shift justification bits
    var i: usize = constants.JUSTIFICATION_BITS_LENGTH - 1;
    while (i > 0) : (i -= 1) {
        state.justificationBits()[i] = state.justificationBits()[i - 1];
    }
    state.justificationBits()[0] = false;

    if (previous_epoch_target_balance * 3 >= total_active_balance * 2) {
        const root = try block_root_helper.getBlockRoot(state, previous_epoch);
        state.setCurrentJustifiedCheckpoint(&consensus.Checkpoint{
            .epoch = previous_epoch,
            .root = root,
        });
        state.justificationBits()[1] = true;
    }

    if (current_epoch_target_balance * 3 >= total_active_balance * 2) {
        const root = try block_root_helper.getBlockRoot(state, current_epoch);
        state.setCurrentJustifiedCheckpoint(&consensus.Checkpoint{
            .epoch = current_epoch,
            .root = root,
        });
        state.justificationBits()[0] = true;
    }

    // Process finalizations
    const bits = state.justificationBits();

    // The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if (allBitsSet(bits[1..4]) and old_previous_justified_checkpoint.epoch + 3 == current_epoch) {
        state.setFinalizedCheckpoint(&old_previous_justified_checkpoint);
    }
    // The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if (allBitsSet(bits[1..3]) and old_previous_justified_checkpoint.epoch + 2 == current_epoch) {
        state.setFinalizedCheckpoint(&old_previous_justified_checkpoint);
    }
    // The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if (allBitsSet(bits[0..3]) and old_current_justified_checkpoint.epoch + 2 == current_epoch) {
        state.setFinalizedCheckpoint(&old_current_justified_checkpoint);
    }
    // The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if (allBitsSet(bits[0..2]) and old_current_justified_checkpoint.epoch + 1 == current_epoch) {
        state.setFinalizedCheckpoint(&old_current_justified_checkpoint);
    }
}

/// processJustificationAndFinalization processes justification and finalization for the current epoch.
///
/// Spec pseudocode definition:
/// def process_justification_and_finalization(state: BeaconState) -> None:
///     # Initial FFG checkpoint values have a `0x00` stub for `root`.
///     # Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
///     if get_current_epoch(state) <= GENESIS_EPOCH + 1:
///         return
///     previous_indices = get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, get_previous_epoch(state))
///     current_indices = get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, get_current_epoch(state))
///     total_active_balance = get_total_active_balance(state)
///     previous_target_balance = get_total_balance(state, previous_indices)
///     current_target_balance = get_total_balance(state, current_indices)
///     weigh_justification_and_finalization(state, total_active_balance, previous_target_balance, current_target_balance)
pub fn processJustificationAndFinalization(state: *consensus.BeaconState, allocator: std.mem.Allocator) !void {
    // Initial FFG checkpoint values have a `0x00` stub for `root`.
    // Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
    if (epoch_helper.getCurrentEpoch(state) <= constants.GENESIS_EPOCH + 1) {
        return;
    }

    const previous_indices = try validator_helper.getUnslashedParticipatingIndices(state, constants.TIMELY_TARGET_FLAG_INDEX, epoch_helper.getPreviousEpoch(state), allocator);
    var previous_indices_map = std.AutoHashMap(primitives.ValidatorIndex, void).init(allocator);
    defer previous_indices_map.deinit();
    for (previous_indices) |index| {
        try previous_indices_map.put(index, {});
    }
    const current_indices = try validator_helper.getUnslashedParticipatingIndices(state, constants.TIMELY_TARGET_FLAG_INDEX, epoch_helper.getCurrentEpoch(state), allocator);
    var current_indices_map = std.AutoHashMap(primitives.ValidatorIndex, void).init(allocator);
    defer current_indices_map.deinit();
    for (current_indices) |index| {
        try current_indices_map.put(index, {});
    }
    const total_active_balance = try balance_helper.getTotalActiveBalance(state, allocator);
    const previous_target_balance = balance_helper.getTotalBalance(state, &previous_indices_map);
    const current_target_balance = balance_helper.getTotalBalance(state, &current_indices_map);

    try weighJustificationAndFinalization(state, total_active_balance, previous_target_balance, current_target_balance);
}

fn allBitsSet(bits: []const bool) bool {
    return !std.mem.containsAtLeast(bool, bits, 1, &[_]bool{false});
}
