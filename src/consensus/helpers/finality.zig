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

pub fn getFinalizationDelay(state: *const consensus.BeaconState) u64 {
    return epoch_helper.getPreviousEpoch(state) - state.finalizedCheckpointEpoch();
}

pub fn isInInactivityLeak(state: *const consensus.BeaconState) bool {
    return getFinalizationDelay(state) > preset.ActivePreset.get().MIN_EPOCHS_TO_INACTIVITY_PENALTY;
}
