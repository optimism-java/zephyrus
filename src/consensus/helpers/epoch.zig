const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");

/// getCurrentEpoch returns the current epoch for the given state.
/// @return The current epoch.
/// Spec pseudocode definition:
/// def get_current_epoch(state: BeaconState) -> Epoch:
/// """
/// Return the current epoch.
/// """
/// return compute_epoch_at_slot(state.slot)
pub fn getCurrentEpoch(state: *const consensus.BeaconState) primitives.Epoch {
    return computeEpochAtSlot(state.slot());
}

/// Return the epoch number at `slot`.
/// @param slot - The slot number.
/// @return The epoch number.
/// @note This function is equivalent to `slot // SLOTS_PER_EPOCH`.
/// Spec pseudocode definition:
///
/// def compute_epoch_at_slot(slot: Slot) -> Epoch:
///    """
///    Return the epoch number at ``slot``.
///    """
///    return Epoch(slot // SLOTS_PER_EPOCH)
pub fn computeEpochAtSlot(slot: primitives.Slot) primitives.Epoch {
    // Return the epoch number at `slot`.
    return @divFloor(slot, preset.ActivePreset.get().SLOTS_PER_EPOCH);
}

test "test compute_epoch_at_slot" {
    preset.ActivePreset.set(preset.Presets.mainnet);
    defer preset.ActivePreset.reset();
    const epoch = computeEpochAtSlot(0);
    try std.testing.expectEqual(0, epoch);

    const epoch2 = computeEpochAtSlot(1);
    try std.testing.expectEqual(0, epoch2);

    const epoch3 = computeEpochAtSlot(10);
    try std.testing.expectEqual(0, epoch3);

    const epoch4 = computeEpochAtSlot(100);
    try std.testing.expectEqual(3, epoch4);
}
