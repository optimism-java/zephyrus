const std = @import("std");
const primitives = @import("../primitives/types.zig");
const preset = @import("../presets/preset.zig");

pub const ActiveConfig = struct {
    var config: Config = undefined;
    var mutex = std.Thread.Mutex{};
    var is_initialized = std.atomic.Value(bool).init(false);

    pub fn set(presets: preset.Presets) void {
        if (is_initialized.swap(true, .acquire)) {
            return;
        }

        mutex.lock();
        defer mutex.unlock();

        config = switch (presets) {
            .mainnet => mainnet_config,
            .minimal => minimal_config,
        };
    }

    pub fn get() Config {
        if (!is_initialized.load(.acquire)) {
            @panic("ActiveConfig not initialized");
        }
        return config;
    }

    pub fn reset() void {
        if (!is_initialized.load(.acquire)) return;

        is_initialized.store(false, .release);

        mutex.lock();
        defer mutex.unlock();
        config = undefined;
    }
};

pub const Config = struct {
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
    GOSSIP_MAX_SIZE: u64,
    MAX_REQUEST_BLOCKS: u64,
    EPOCHS_PER_SUBNET_SUBSCRIPTION: u64,
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: u64,
    MAX_CHUNK_SIZE: u64,
    TTFB_TIMEOUT: u64,
    RESP_TIMEOUT: u64,
    ATTESTATION_PROPAGATION_SLOT_RANGE: u64,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY: u64,
    MESSAGE_DOMAIN_INVALID_SNAPPY: primitives.DomainType,
    MESSAGE_DOMAIN_VALID_SNAPPY: primitives.DomainType,
    SUBNETS_PER_NODE: u64,
    ATTESTATION_SUBNET_COUNT: u64,
    ATTESTATION_SUBNET_EXTRA_BITS: u64,
    ATTESTATION_SUBNET_PREFIX_BITS: u64,
    INACTIVITY_SCORE_BIAS: u64,
    INACTIVITY_SCORE_RECOVERY_RATE: u64,
    ALTAIR_FORK_VERSION: primitives.Version,
    ALTAIR_FORK_EPOCH: primitives.Epoch,
    TERMINAL_TOTAL_DIFFICULTY: u256,
    TERMINAL_BLOCK_HASH: primitives.Hash32,
    TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: u64,
    BELLATRIX_FORK_VERSION: primitives.Version,
    BELLATRIX_FORK_EPOCH: primitives.Epoch,
    CAPELLA_FORK_VERSION: primitives.Version,
    CAPELLA_FORK_EPOCH: primitives.Epoch,
    MAX_BLOBS_PER_BLOCK: u64,
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: u64,
    DENEB_FORK_VERSION: primitives.Version,
    DENEB_FORK_EPOCH: primitives.Epoch,
    MAX_REQUEST_BLOCKS_DENEB: u64,
    MAX_REQUEST_BLOB_SIDECARS: u64,
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: u64,
    BLOB_SIDECAR_SUBNET_COUNT: u64,
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: primitives.Gwei,
    MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: primitives.Gwei,
    ELECTRA_FORK_VERSION: primitives.Version,
    ELECTRA_FORK_EPOCH: primitives.Epoch,
};

pub const mainnet_config = Config{
    .PRESET_BASE = "mainnet",
    .MIN_GENESIS_ACTIVE_VALIDATOR_COUNT = 16384,
    .MIN_GENESIS_TIME = 1606824000,
    .GENESIS_FORK_VERSION = .{ 0x00, 0x00, 0x00, 0x00 },
    .GENESIS_DELAY = 604800,
    .SECONDS_PER_SLOT = 12,
    .SECONDS_PER_ETH1_BLOCK = 14,
    .MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256,
    .SHARD_COMMITTEE_PERIOD = 256,
    .ETH1_FOLLOW_DISTANCE = 2048,
    .EJECTION_BALANCE = 16000000000,
    .MIN_PER_EPOCH_CHURN_LIMIT = 4,
    .CHURN_LIMIT_QUOTIENT = 65536,
    .PROPOSER_SCORE_BOOST = 40,
    .REORG_HEAD_WEIGHT_THRESHOLD = 20,
    .REORG_PARENT_WEIGHT_THRESHOLD = 160,
    .REORG_MAX_EPOCHS_SINCE_FINALIZATION = 2,
    .GOSSIP_MAX_SIZE = 10485760,
    .MAX_REQUEST_BLOCKS = 1024,
    .EPOCHS_PER_SUBNET_SUBSCRIPTION = 256,
    .MIN_EPOCHS_FOR_BLOCK_REQUESTS = 33024,
    .MAX_CHUNK_SIZE = 10485760,
    .TTFB_TIMEOUT = 5,
    .RESP_TIMEOUT = 10,
    .ATTESTATION_PROPAGATION_SLOT_RANGE = 32,
    .MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500,
    .MESSAGE_DOMAIN_INVALID_SNAPPY = .{ 0x00, 0x00, 0x00, 0x00 },
    .MESSAGE_DOMAIN_VALID_SNAPPY = .{ 0x01, 0x00, 0x00, 0x00 },
    .SUBNETS_PER_NODE = 2,
    .ATTESTATION_SUBNET_COUNT = 64,
    .ATTESTATION_SUBNET_EXTRA_BITS = 0,
    .ATTESTATION_SUBNET_PREFIX_BITS = 6,
    .INACTIVITY_SCORE_BIAS = 4,
    .INACTIVITY_SCORE_RECOVERY_RATE = 16,
    .ALTAIR_FORK_VERSION = .{ 0x01, 0x00, 0x00, 0x00 },
    .ALTAIR_FORK_EPOCH = 74240,
    .TERMINAL_TOTAL_DIFFICULTY = 58750000000000000000000,
    .TERMINAL_BLOCK_HASH = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH = 18446744073709551615,
    .BELLATRIX_FORK_VERSION = .{ 0x02, 0x00, 0x00, 0x00 },
    .BELLATRIX_FORK_EPOCH = 144896,
    .CAPELLA_FORK_VERSION = .{ 0x03, 0x00, 0x00, 0x00 },
    .CAPELLA_FORK_EPOCH = 194048,
    .MAX_BLOBS_PER_BLOCK = 6,
    .MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT = 8,
    .DENEB_FORK_VERSION = .{ 0x04, 0x00, 0x00, 0x00 },
    .DENEB_FORK_EPOCH = 269568,
    .MAX_REQUEST_BLOCKS_DENEB = 128,
    .MAX_REQUEST_BLOB_SIDECARS = 768,
    .MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 4096,
    .BLOB_SIDECAR_SUBNET_COUNT = 6,
    .MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA = 128000000000,
    .MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT = 256000000000,
    .ELECTRA_FORK_VERSION = .{ 0x05, 0x00, 0x00, 0x00 },
    .ELECTRA_FORK_EPOCH = 18446744073709551615,
};

pub const minimal_config = Config{
    .PRESET_BASE = "minimal",
    .MIN_GENESIS_ACTIVE_VALIDATOR_COUNT = 64,
    .MIN_GENESIS_TIME = 1578009600,
    .GENESIS_FORK_VERSION = .{ 0x00, 0x00, 0x00, 0x01 },
    .GENESIS_DELAY = 300,
    .SECONDS_PER_SLOT = 6,
    .SECONDS_PER_ETH1_BLOCK = 14,
    .MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256,
    .SHARD_COMMITTEE_PERIOD = 64,
    .ETH1_FOLLOW_DISTANCE = 16,
    .EJECTION_BALANCE = 16000000000,
    .MIN_PER_EPOCH_CHURN_LIMIT = 2,
    .CHURN_LIMIT_QUOTIENT = 32,
    .PROPOSER_SCORE_BOOST = 40,
    .REORG_HEAD_WEIGHT_THRESHOLD = 20,
    .REORG_PARENT_WEIGHT_THRESHOLD = 160,
    .REORG_MAX_EPOCHS_SINCE_FINALIZATION = 2,
    .GOSSIP_MAX_SIZE = 10485760,
    .MAX_REQUEST_BLOCKS = 1024,
    .EPOCHS_PER_SUBNET_SUBSCRIPTION = 256,
    .MIN_EPOCHS_FOR_BLOCK_REQUESTS = 272,
    .MAX_CHUNK_SIZE = 10485760,
    .TTFB_TIMEOUT = 5,
    .RESP_TIMEOUT = 10,
    .ATTESTATION_PROPAGATION_SLOT_RANGE = 32,
    .MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500,
    .MESSAGE_DOMAIN_INVALID_SNAPPY = .{ 0x00, 0x00, 0x00, 0x00 },
    .MESSAGE_DOMAIN_VALID_SNAPPY = .{ 0x01, 0x00, 0x00, 0x00 },
    .SUBNETS_PER_NODE = 2,
    .ATTESTATION_SUBNET_COUNT = 64,
    .ATTESTATION_SUBNET_EXTRA_BITS = 0,
    .ATTESTATION_SUBNET_PREFIX_BITS = 6,
    .INACTIVITY_SCORE_BIAS = 4,
    .INACTIVITY_SCORE_RECOVERY_RATE = 16,
    .ALTAIR_FORK_VERSION = .{ 0x01, 0x00, 0x00, 0x01 },
    .ALTAIR_FORK_EPOCH = std.math.maxInt(u64),
    .TERMINAL_TOTAL_DIFFICULTY = 115792089237316195423570985008687907853269984665640564039457584007913129638912,
    .TERMINAL_BLOCK_HASH = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH = std.math.maxInt(u64),
    .BELLATRIX_FORK_VERSION = .{ 0x02, 0x00, 0x00, 0x01 },
    .BELLATRIX_FORK_EPOCH = std.math.maxInt(u64),
    .CAPELLA_FORK_VERSION = .{ 0x03, 0x00, 0x00, 0x01 },
    .CAPELLA_FORK_EPOCH = std.math.maxInt(u64),
    .MAX_BLOBS_PER_BLOCK = 6,
    .MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT = 4,
    .DENEB_FORK_VERSION = .{ 0x04, 0x00, 0x00, 0x01 },
    .DENEB_FORK_EPOCH = std.math.maxInt(u64),
    .MAX_REQUEST_BLOCKS_DENEB = 128,
    .MAX_REQUEST_BLOB_SIDECARS = 768,
    .MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 4096,
    .BLOB_SIDECAR_SUBNET_COUNT = 6,
    .MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA = 64000000000,
    .MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT = 128000000000,
    .ELECTRA_FORK_VERSION = .{ 0x05, 0x00, 0x00, 0x01 },
    .ELECTRA_FORK_EPOCH = std.math.maxInt(u64),
};

test "mainnet config has correct MIN_GENESIS_ACTIVE_VALIDATOR_COUNT" {
    try std.testing.expectEqual(mainnet_config.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, 16384);
}

test "mainnet config has correct GENESIS_FORK_VERSION" {
    try std.testing.expectEqual(mainnet_config.GENESIS_FORK_VERSION, .{ 0x00, 0x00, 0x00, 0x00 });
}

test "mainnet config has correct TERMINAL_TOTAL_DIFFICULTY" {
    try std.testing.expectEqual(mainnet_config.TERMINAL_TOTAL_DIFFICULTY, 58750000000000000000000);
}

test "minimal config has correct MIN_GENESIS_ACTIVE_VALIDATOR_COUNT" {
    try std.testing.expectEqual(minimal_config.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, 64);
}

test "minimal config has correct GENESIS_FORK_VERSION" {
    try std.testing.expectEqual(minimal_config.GENESIS_FORK_VERSION, .{ 0x00, 0x00, 0x00, 0x01 });
}

test "minimal config has correct TERMINAL_TOTAL_DIFFICULTY" {
    try std.testing.expectEqual(minimal_config.TERMINAL_TOTAL_DIFFICULTY, 115792089237316195423570985008687907853269984665640564039457584007913129638912);
}

test "mainnet config has correct MAX_BLOBS_PER_BLOCK" {
    try std.testing.expectEqual(mainnet_config.MAX_BLOBS_PER_BLOCK, 6);
}

test "mainnet config has correct DENEB_FORK_VERSION" {
    try std.testing.expectEqual(mainnet_config.DENEB_FORK_VERSION, .{ 0x04, 0x00, 0x00, 0x00 });
}

test "mainnet config has correct MAX_REQUEST_BLOCKS_DENEB" {
    try std.testing.expectEqual(mainnet_config.MAX_REQUEST_BLOCKS_DENEB, 128);
}

test "mainnet config has correct BLOB_SIDECAR_SUBNET_COUNT" {
    try std.testing.expectEqual(mainnet_config.BLOB_SIDECAR_SUBNET_COUNT, 6);
}

test "minimal config has correct ALTAIR_FORK_VERSION" {
    try std.testing.expectEqual(minimal_config.ALTAIR_FORK_VERSION, .{ 0x01, 0x00, 0x00, 0x01 });
}

test "minimal config has correct BELLATRIX_FORK_VERSION" {
    try std.testing.expectEqual(minimal_config.BELLATRIX_FORK_VERSION, .{ 0x02, 0x00, 0x00, 0x01 });
}

test "minimal config has correct CAPELLA_FORK_VERSION" {
    try std.testing.expectEqual(minimal_config.CAPELLA_FORK_VERSION, .{ 0x03, 0x00, 0x00, 0x01 });
}

test "minimal config has correct ELECTRA_FORK_VERSION" {
    try std.testing.expectEqual(minimal_config.ELECTRA_FORK_VERSION, .{ 0x05, 0x00, 0x00, 0x01 });
}

test "minimal config has correct MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT" {
    try std.testing.expectEqual(minimal_config.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, 4);
}

test "minimal config has correct MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA" {
    try std.testing.expectEqual(minimal_config.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, 64000000000);
}

test "test ActiveConfig" {
    ActiveConfig.set(preset.Presets.mainnet);
    defer ActiveConfig.reset();
    const active_config = ActiveConfig.get();
    try std.testing.expectEqual(active_config.PRESET_BASE, "mainnet");
}
