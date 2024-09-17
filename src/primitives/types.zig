const std = @import("std");

pub const Bytes1 = [1]u8;
pub const Bytes4 = [4]u8;
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