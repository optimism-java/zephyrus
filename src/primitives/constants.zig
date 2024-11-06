const std = @import("std");
const types = @import("types.zig");

pub const UINT64_MAX: u64 = std.math.maxInt(u64);
pub const UINT64_MAX_SQRT: u64 = 4294967295;
pub const GENESIS_SLOT: types.Slot = 0;
pub const GENESIS_EPOCH: types.Epoch = 0;
pub const FAR_FUTURE_EPOCH: types.Epoch = std.math.maxInt(u64);
pub const BASE_REWARDS_PER_EPOCH: u64 = 4;
pub const DEPOSIT_CONTRACT_TREE_DEPTH: u64 = 32;
pub const SYNC_COMMITTEE_SUBNET_COUNT: usize = 4;
pub const JUSTIFICATION_BITS_LENGTH: u64 = 4;
pub const ENDIANNESS = .little;
pub const BLS_WITHDRAWAL_PREFIX: types.Bytes1 = 0x00;
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: types.Bytes1 = 0x01;
pub const DOMAIN_BEACON_PROPOSER: types.DomainType = .{ 0x00, 0x00, 0x00, 0x00 };
pub const DOMAIN_BEACON_ATTESTER: types.DomainType = .{ 0x01, 0x00, 0x00, 0x00 };
pub const DOMAIN_RANDAO: types.DomainType = .{ 0x02, 0x00, 0x00, 0x00 };
pub const DOMAIN_DEPOSIT: types.DomainType = .{ 0x03, 0x00, 0x00, 0x00 };
pub const DOMAIN_VOLUNTARY_EXIT: types.DomainType = .{ 0x04, 0x00, 0x00, 0x00 };
pub const DOMAIN_SELECTION_PROOF: types.DomainType = .{ 0x05, 0x00, 0x00, 0x00 };
pub const DOMAIN_AGGREGATE_AND_PROOF: types.DomainType = .{ 0x06, 0x00, 0x00, 0x00 };
pub const DOMAIN_APPLICATION_MASK: types.DomainType = .{ 0x00, 0x00, 0x00, 0x01 };
pub const INTERVALS_PER_SLOT: u64 = 3;
pub const NODE_ID_BITS: u64 = 256;
pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = std.math.pow(u64, 2, 4);
pub const ETH_TO_GWEI: u64 = std.math.pow(u64, 10, 9);
pub const SAFETY_DECAY: u64 = 10;

pub const EXECUTION_PAYLOAD_GINDEX: usize = 25;
pub const FINALIZED_ROOT_GINDEX: usize = 105;
pub const FINALIZED_ROOT_GINDEX_ELECTRA: usize = 169;
pub const CURRENT_SYNC_COMMITTEE_GINDEX: usize = 54;
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: usize = 86;
pub const NEXT_SYNC_COMMITTEE_GINDEX: usize = 55;
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: usize = 87;

pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const MAX_BLOBS_PER_BLOCK: usize = 6;

pub const PROPOSER_WEIGHT: u64 = 8;
pub const WEIGHT_DENOMINATOR: u64 = 64;
pub const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = std.math.maxInt(u64);

pub const COMPOUNDING_WITHDRAWAL_PREFIX: types.Bytes1 = 0x02;
pub const DOMAIN_SYNC_COMMITTEE: types.DomainType = .{ 0x07, 0x00, 0x00, 0x00 };
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: types.DomainType = .{ 0x08, 0x00, 0x00, 0x00 };

pub const TIMELY_TARGET_FLAG_INDEX: u3 = 1;
pub const TIMELY_HEAD_FLAG_INDEX: u3 = 2;
pub const TIMELY_SOURCE_WEIGHT: u64 = 14;
pub const TIMELY_TARGET_WEIGHT: u64 = 26;
pub const TIMELY_HEAD_WEIGHT: u64 = 14;

pub const PARTICIPATION_FLAG_WEIGHTS = [_]u64{
    TIMELY_SOURCE_WEIGHT,
    TIMELY_TARGET_WEIGHT,
    TIMELY_HEAD_WEIGHT,
};
