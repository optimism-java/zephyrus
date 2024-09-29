const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("utils.zig");
const preset = @import("../presets/preset.zig");

pub const Bytes1 = [1]u8;
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

pub const FinalityBranch = union(enum) {
    Altair: FinalityBranchAltair,
    Bellatrix: FinalityBranchAltair,
    Capella: FinalityBranchAltair,
    Deneb: FinalityBranchAltair,
    Electra: FinalityBranchElectra,
};

pub const NextSyncCommitteeBranch = union(enum) {
    Altair: NextSyncCommitteeBranchAltair,
    Bellatrix: NextSyncCommitteeBranchAltair,
    Capella: NextSyncCommitteeBranchAltair,
    Deneb: NextSyncCommitteeBranchAltair,
    Electra: NextSyncCommitteeBranchElectra,
};

pub const CurrentSyncCommitteeBranch = union(enum) {
    Altair: CurrentSyncCommitteeBranchAltair,
    Bellatrix: CurrentSyncCommitteeBranchAltair,
    Capella: CurrentSyncCommitteeBranchAltair,
    Deneb: CurrentSyncCommitteeBranchAltair,
    Electra: CurrentSyncCommitteeBranchElectra,
};

pub fn Transaction(comptime T: preset.BeaconPreset) type {
    return [T.MAX_BYTES_PER_TRANSACTION]u8;
}

pub const ForkType = enum {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
};

test "test ExecutionBranch length" {
    const ExecutionBranchLength = @typeInfo(ExecutionBranch).Array.len;
    try std.testing.expectEqual(4, ExecutionBranchLength);
}

test "test FinalityBranchElectra length" {
    const FinalityBranchLength = @typeInfo(FinalityBranchElectra).Array.len;
    try std.testing.expectEqual(7, FinalityBranchLength);
}

test "test FinalityBranch length" {
    const FinalityBranchLength = @typeInfo(FinalityBranchAltair).Array.len;
    try std.testing.expectEqual(6, FinalityBranchLength);
}

test "test FinalityBranch Union length" {
    const FinalityBranchLength = @typeInfo(@typeInfo(FinalityBranch).Union.fields[0].type).Array.len;
    try std.testing.expectEqual(6, FinalityBranchLength);
    const FinalityBranchLength2 = @typeInfo(@typeInfo(FinalityBranch).Union.fields[1].type).Array.len;
    try std.testing.expectEqual(6, FinalityBranchLength2);
    const FinalityBranchLength3 = @typeInfo(@typeInfo(FinalityBranch).Union.fields[2].type).Array.len;
    try std.testing.expectEqual(6, FinalityBranchLength3);
    const FinalityBranchLength4 = @typeInfo(@typeInfo(FinalityBranch).Union.fields[3].type).Array.len;
    try std.testing.expectEqual(6, FinalityBranchLength4);
    const FinalityBranchLength5 = @typeInfo(@typeInfo(FinalityBranch).Union.fields[4].type).Array.len;
    try std.testing.expectEqual(7, FinalityBranchLength5);
}

test "test ForkType length" {
    const ForkTypeLength = @typeInfo(ForkType).Enum.fields.len;
    try std.testing.expectEqual(6, ForkTypeLength);
}
