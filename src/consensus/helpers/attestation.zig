const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");

/// isSlashableAttestationData checks if two attestations are slashable according to Casper FFG rules.
/// @param data_1 The first attestation data.
/// @param data_2 The second attestation data.
/// @return True if the attestations are slashable, false otherwise.
/// Spec pseudocode definition:
/// def is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
///    """
///    Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
///    """
///    return (
///          # Double vote
///        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
///         # Surround vote
///        (data_1.source.epoch < data_2.source.epoch and data_2.target.epoch < data_1.target.epoch)
///     )
pub fn isSlashableAttestationData(data1: consensus.AttestationData, data2: consensus.AttestationData) bool {
    // Check if `data_1` and `data_2` are slashable according to Casper FFG rules.
    return (
    // Double vote
        (!std.meta.eql(data1, data2) and data1.target.epoch == data2.target.epoch) or
        // Surround vote
        (data1.source.epoch < data2.source.epoch and data2.target.epoch < data1.target.epoch));
}

test "test isSlashableAttestationData" {
    const data1 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
    };

    const data2 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
    };

    try std.testing.expectEqual(isSlashableAttestationData(data1, data2), false);

    const data3 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
    };

    const data4 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
    };

    try std.testing.expectEqual(isSlashableAttestationData(data3, data4), true);
    try std.testing.expectEqual(isSlashableAttestationData(data1, data4), false);
}
