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

// pub fn weighJustificationAndFinalization(
//     state: *consensus.BeaconState,
//     total_active_balance: primitives.Gwei,
//     previous_epoch_target_balance: primitives.Gwei,
//     current_epoch_target_balance: primitives.Gwei,
// ) void {
//     const previous_epoch = epoch_helper.getPreviousEpoch(state);
//     const current_epoch = epoch_helper.getCurrentEpoch(state);
//     const old_previous_justified_checkpoint = state.p;
//     const old_current_justified_checkpoint = state.current_justified_checkpoint;
//
//     // Process justifications
//     state.previous_justified_checkpoint = state.current_justified_checkpoint;
//
//     // Shift justification bits
//     var i: usize = constants.JUSTIFICATION_BITS_LENGTH - 1;
//     while (i > 0) : (i -= 1) {
//         state.justification_bits[i] = state.justification_bits[i - 1];
//     }
//     state.justification_bits[0] = 0;
//
//     if (previous_epoch_target_balance * 3 >= total_active_balance * 2) {
//         state.current_justified_checkpoint = consensus.Checkpoint{
//             .epoch = previous_epoch,
//             .root = getBlockRoot(state, previous_epoch),
//         };
//         state.justification_bits[1] = 1;
//     }
//
//     if (current_epoch_target_balance * 3 >= total_active_balance * 2) {
//         state.current_justified_checkpoint = Checkpoint{
//             .epoch = current_epoch,
//             .root = getBlockRoot(state, current_epoch),
//         };
//         state.justification_bits[0] = 1;
//     }
//
//     // Process finalizations
//     const bits = state.justification_bits;
//
//     // The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
//     if (allBitsSet(bits[1..4]) and old_previous_justified_checkpoint.epoch + 3 == current_epoch) {
//         state.finalized_checkpoint = old_previous_justified_checkpoint;
//     }
//     // The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
//     if (allBitsSet(bits[1..3]) and old_previous_justified_checkpoint.epoch + 2 == current_epoch) {
//         state.finalized_checkpoint = old_previous_justified_checkpoint;
//     }
//     // The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
//     if (allBitsSet(bits[0..3]) and old_current_justified_checkpoint.epoch + 2 == current_epoch) {
//         state.finalized_checkpoint = old_current_justified_checkpoint;
//     }
//     // The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
//     if (allBitsSet(bits[0..2]) and old_current_justified_checkpoint.epoch + 1 == current_epoch) {
//         state.finalized_checkpoint = old_current_justified_checkpoint;
//     }
// }

fn allBitsSet(bits: []const bool) bool {
    return !std.mem.containsAtLeast(bool, bits, 1, false);
}
