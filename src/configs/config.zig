const std = @import("std");
const primitives = @import("../primitives/types.zig");

const Configuration = struct {
    PRESET_BASE: []const u8,
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: u64,
    MIN_GENESIS_TIME: u64,
    GENESIS_FORK_VERSION: primitives.Version,
    GENESIS_DELAY: u64,
    SECONDS_PER_SLOT: u64,
    SECONDS_PER_ETH1_BLOCK: u64,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64,
    SHARD_COMMITTEE_PERIOD: u64,
    ETH1_FOLLOW_DISTANCE: u64,
    EJECTION_BALANCE: primitives.Gwei,
    MIN_PER_EPOCH_CHURN_LIMIT: u64,
    CHURN_LIMIT_QUOTIENT: u64,
    PROPOSER_SCORE_BOOST: u64,
    REORG_HEAD_WEIGHT_THRESHOLD: u64,
    REORG_PARENT_WEIGHT_THRESHOLD: u64,
    REORG_MAX_EPOCHS_SINCE_FINALIZATION: primitives.Epoch,
    GOSSIP_MAX_SIZE: i32,
    MAX_REQUEST_BLOCKS: i32,
    EPOCHS_PER_SUBNET_SUBSCRIPTION: i32,
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: i32,
    MAX_CHUNK_SIZE: i32,
    TTFB_TIMEOUT: i32,
    RESP_TIMEOUT: i32,
    ATTESTATION_PROPAGATION_SLOT_RANGE: i32,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY: i32,
    MESSAGE_DOMAIN_INVALID_SNAPPY: primitives.DomainType,
    MESSAGE_DOMAIN_VALID_SNAPPY: primitives.DomainType,
    SUBNETS_PER_NODE: i32,
    ATTESTATION_SUBNET_COUNT: i32,
    ATTESTATION_SUBNET_EXTRA_BITS: i32,
    ATTESTATION_SUBNET_PREFIX_BITS: i32,
};
