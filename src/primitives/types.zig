const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("utils.zig");
const preset = @import("../presets/preset.zig");

pub const Bytes1 = u8;
pub const Bytes4 = [4]u8;
pub const Bytes20 = [20]u8;
pub const Bytes32 = [32]u8;
pub const Bytes48 = [48]u8;
pub const Bytes96 = [96]u8;
pub const BitVector = std.ArrayList(u8);

pub const Slot = u64;
pub const Epoch = u64;
pub const CommitteeIndex = u64;
pub const ValidatorIndex = u64;
pub const WithdrawalIndex = u64;
pub const Gwei = u64;
pub const Root = Bytes32;
pub const Hash32 = Bytes32;
pub const Version = Bytes4;
pub const DomainType = Bytes4;
pub const ForkDigest = Bytes4;
pub const Domain = Bytes32;
pub const BLSPubkey = Bytes48;
pub const BLSSignature = Bytes96;
pub const NodeID = u256;
pub const SubnetID = u64;
pub const Ether = u64;
pub const ExecutionAddress = Bytes20;
pub const BlobIndex = u64;
pub const KZGCommitment = Bytes48;
pub const KZGProof = Bytes48;

pub const Blob = [constants.BYTES_PER_FIELD_ELEMENT * constants.FIELD_ELEMENTS_PER_BLOB]u8;

pub const ExecutionBranch = [utils.floorLog2(constants.EXECUTION_PAYLOAD_GINDEX)]Bytes32;

pub const FinalityBranchElectra = [utils.floorLog2(constants.FINALIZED_ROOT_GINDEX_ELECTRA)]Bytes32;

pub const FinalityBranchAltair = [utils.floorLog2(constants.FINALIZED_ROOT_GINDEX)]Bytes32;

pub const NextSyncCommitteeBranchAltair = [utils.floorLog2(constants.NEXT_SYNC_COMMITTEE_GINDEX)]Bytes32;

pub const NextSyncCommitteeBranchElectra = [utils.floorLog2(constants.NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA)]Bytes32;

pub const CurrentSyncCommitteeBranchAltair = [utils.floorLog2(constants.CURRENT_SYNC_COMMITTEE_GINDEX)]Bytes32;

pub const CurrentSyncCommitteeBranchElectra = [utils.floorLog2(constants.CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA)]Bytes32;

pub const FinalityBranch = union(ForkType) {
    phase0: type,
    altair: FinalityBranchAltair,
    bellatrix: FinalityBranchAltair,
    capella: FinalityBranchAltair,
    deneb: FinalityBranchAltair,
    electra: FinalityBranchElectra,
};

pub const NextSyncCommitteeBranch = union(ForkType) {
    phase0: type,
    altair: NextSyncCommitteeBranchAltair,
    bellatrix: NextSyncCommitteeBranchAltair,
    capella: NextSyncCommitteeBranchAltair,
    deneb: NextSyncCommitteeBranchAltair,
    electra: NextSyncCommitteeBranchElectra,
};

pub const CurrentSyncCommitteeBranch = union(ForkType) {
    phase0: type,
    altair: CurrentSyncCommitteeBranchAltair,
    bellatrix: CurrentSyncCommitteeBranchAltair,
    capella: CurrentSyncCommitteeBranchAltair,
    deneb: CurrentSyncCommitteeBranchAltair,
    electra: CurrentSyncCommitteeBranchElectra,
};

pub const Transaction = []u8;

pub const ForkType = enum {
    phase0,
    altair,
    bellatrix,
    capella,
    deneb,
    electra,
};

pub const DomainTypeSize = @sizeOf(DomainType);
pub const EpochSize = @sizeOf(Epoch);
pub const Bytes32Size = @sizeOf(Bytes32);

/// computeActivationExitEpoch computes the activation exit epoch for a given epoch.
/// @param epoch The epoch to compute the activation exit epoch for.
/// @return The activation exit epoch.
/// Spec pseudocode definition:
///
/// def compute_activation_exit_epoch(epoch: Epoch) -> Epoch:
///     """
///     Return the epoch during which validator activations and exits initiated in ``epoch`` take effect.
///     """
///    return Epoch(epoch + 1 + MAX_SEED_LOOKAHEAD)
pub fn computeActivationExitEpoch(epoch: Epoch) Epoch {
    return @intCast(epoch + 1 + preset.ActivePreset.get().MAX_SEED_LOOKAHEAD);
}

test "test ExecutionBranch length" {
    const ExecutionBranchLength = @typeInfo(ExecutionBranch).array.len;
    try std.testing.expectEqual(4, ExecutionBranchLength);
}

test "test FinalityBranchElectra length" {
    const FinalityBranchLength = @typeInfo(FinalityBranchElectra).array.len;
    try std.testing.expectEqual(7, FinalityBranchLength);
}

test "test FinalityBranch length" {
    const FinalityBranchLength = @typeInfo(FinalityBranchAltair).array.len;
    try std.testing.expectEqual(6, FinalityBranchLength);
}

test "test FinalityBranch Union length" {
    const FinalityBranchLength = @typeInfo(@typeInfo(FinalityBranch).@"union".fields[1].type).array.len;
    try std.testing.expectEqual(6, FinalityBranchLength);
    const FinalityBranchLength2 = @typeInfo(@typeInfo(FinalityBranch).@"union".fields[2].type).array.len;
    try std.testing.expectEqual(6, FinalityBranchLength2);
    const FinalityBranchLength3 = @typeInfo(@typeInfo(FinalityBranch).@"union".fields[3].type).array.len;
    try std.testing.expectEqual(6, FinalityBranchLength3);
    const FinalityBranchLength4 = @typeInfo(@typeInfo(FinalityBranch).@"union".fields[4].type).array.len;
    try std.testing.expectEqual(6, FinalityBranchLength4);
    const FinalityBranchLength5 = @typeInfo(@typeInfo(FinalityBranch).@"union".fields[5].type).array.len;
    try std.testing.expectEqual(7, FinalityBranchLength5);
}

test "test ForkType length" {
    const ForkTypeLength = @typeInfo(ForkType).@"enum".fields.len;
    try std.testing.expectEqual(6, ForkTypeLength);
}

test "test compute_activation_exit_epochs" {
    preset.ActivePreset.set(preset.Presets.mainnet);
    defer preset.ActivePreset.reset();
    const epoch: Epoch = 5;
    const result = computeActivationExitEpoch(epoch);
    try std.testing.expectEqual(result, 5 + 1 + preset.ActivePreset.get().MAX_SEED_LOOKAHEAD);
}
