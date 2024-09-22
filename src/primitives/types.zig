const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("utils.zig");

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

pub const ExecutionBranch = [utils.floorLog2(constants.EXECUTION_PAYLOAD_GINDEX)]Bytes32;

pub const FinalityBranch = [utils.floorLog2(constants.FINALIZED_ROOT_GINDEX_ELECTRA)]Bytes32;

test "test ExecutionBranch length" {
    const ExecutionBranchLength = @typeInfo(ExecutionBranch).Array.len;
    try std.testing.expectEqual(4, ExecutionBranchLength);
}

test "test FinalityBranch length" {
    const FinalityBranchLength = @typeInfo(FinalityBranch).Array.len;
    try std.testing.expectEqual(7, FinalityBranchLength);
}
