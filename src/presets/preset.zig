const std = @import("std");
const primitives = @import("../primitives/types.zig");

pub const ActivePreset = struct {
    var preset: BeaconPreset = undefined;
    var mutex = std.Thread.Mutex{};
    var is_initialized = std.atomic.Value(bool).init(false);

    pub fn set(presets: Presets) void {
        if (is_initialized.swap(true, .acquire)) {
            return;
        }

        mutex.lock();
        defer mutex.unlock();

        preset = switch (presets) {
            .mainnet => mainnet_preset,
            .minimal => minimal_preset,
        };
    }

    pub fn get() BeaconPreset {
        if (!is_initialized.load(.acquire)) {
            @panic("ActivePreset not initialized");
        }
        return preset;
    }

    pub fn reset() void {
        if (!is_initialized.load(.acquire)) return;

        is_initialized.store(false, .release);

        mutex.lock();
        defer mutex.unlock();
        preset = undefined;
    }
};

pub const Presets = enum {
    mainnet,
    minimal,
};

/// Compile-time chain configuration
pub const BeaconPreset = struct {
    // Misc
    MAX_COMMITTEES_PER_SLOT: u64,
    TARGET_COMMITTEE_SIZE: u64,
    MAX_VALIDATORS_PER_COMMITTEE: u64,

    SHUFFLE_ROUND_COUNT: u64,

    HYSTERESIS_QUOTIENT: u64,
    HYSTERESIS_DOWNWARD_MULTIPLIER: u64,
    HYSTERESIS_UPWARD_MULTIPLIER: u64,

    // Gwei Values
    MIN_DEPOSIT_AMOUNT: primitives.Gwei,
    MAX_EFFECTIVE_BALANCE: primitives.Gwei,
    EFFECTIVE_BALANCE_INCREMENT: primitives.Gwei,

    // Time parameters
    MIN_ATTESTATION_INCLUSION_DELAY: u64,
    SLOTS_PER_EPOCH: u64,
    MIN_SEED_LOOKAHEAD: u64,
    MAX_SEED_LOOKAHEAD: u64,
    EPOCHS_PER_ETH1_VOTING_PERIOD: u64,
    SLOTS_PER_HISTORICAL_ROOT: u64,
    MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64,

    // State vector lengths
    EPOCHS_PER_HISTORICAL_VECTOR: u64,
    EPOCHS_PER_SLASHINGS_VECTOR: u64,
    HISTORICAL_ROOTS_LIMIT: u64,
    VALIDATOR_REGISTRY_LIMIT: u64,

    // Reward and penalty quotients
    BASE_REWARD_FACTOR: u64,
    WHISTLEBLOWER_REWARD_QUOTIENT: u64,
    PROPOSER_REWARD_QUOTIENT: u64,
    INACTIVITY_PENALTY_QUOTIENT: u64,
    MIN_SLASHING_PENALTY_QUOTIENT: u64,
    PROPORTIONAL_SLASHING_MULTIPLIER: u64,

    // Max operations per block
    MAX_PROPOSER_SLASHINGS: u64,
    MAX_ATTESTER_SLASHINGS: u64,
    MAX_ATTESTATIONS: u64,
    MAX_DEPOSITS: u64,
    MAX_VOLUNTARY_EXITS: u64,

    // ALTAIR
    SYNC_COMMITTEE_SIZE: u64,
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64,
    INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64,
    MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64,
    PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64,
    MIN_SYNC_COMMITTEE_PARTICIPANTS: u64,
    UPDATE_TIMEOUT: u64,

    // BELLATRIX
    INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64,
    MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64,
    PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64,
    MAX_BYTES_PER_TRANSACTION: u64,
    MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    BYTES_PER_LOGS_BLOOM: u64,
    MAX_EXTRA_DATA_BYTES: u64,

    // CAPELLA
    MAX_BLS_TO_EXECUTION_CHANGES: u64,
    MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64,

    // DENEB
    FIELD_ELEMENTS_PER_BLOB: u64,
    MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    MAX_BLOBS_PER_BLOCK: u64,
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: u64,

    // ELECTRA
    MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    MAX_ATTESTER_SLASHINGS_ELECTRA: u64,
    MAX_ATTESTATIONS_ELECTRA: u64,
    MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64,
    MAX_EFFECTIVE_BALANCE_ELECTRA: primitives.Gwei,
    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64,
    MIN_ACTIVATION_BALANCE: primitives.Gwei,
    PENDING_BALANCE_DEPOSITS_LIMIT: u64,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    PENDING_CONSOLIDATIONS_LIMIT: u64,
    MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
    WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64,
};

/// Mainnet preset
/// https://github.com/ethereum/consensus-specs/tree/dev/presets/mainnet
pub const mainnet_preset = BeaconPreset{
    // Misc
    .MAX_COMMITTEES_PER_SLOT = 64,
    .TARGET_COMMITTEE_SIZE = 128,
    .MAX_VALIDATORS_PER_COMMITTEE = 2048,

    .SHUFFLE_ROUND_COUNT = 90,

    .HYSTERESIS_QUOTIENT = 4,
    .HYSTERESIS_DOWNWARD_MULTIPLIER = 1,
    .HYSTERESIS_UPWARD_MULTIPLIER = 5,

    // Gwei Values
    .MIN_DEPOSIT_AMOUNT = 1000000000,
    .MAX_EFFECTIVE_BALANCE = 32000000000,
    .EFFECTIVE_BALANCE_INCREMENT = 1000000000,

    // Time parameters
    .MIN_ATTESTATION_INCLUSION_DELAY = 1,
    .SLOTS_PER_EPOCH = 32,
    .MIN_SEED_LOOKAHEAD = 1,
    .MAX_SEED_LOOKAHEAD = 4,
    .EPOCHS_PER_ETH1_VOTING_PERIOD = 64,
    .SLOTS_PER_HISTORICAL_ROOT = 8192,
    .MIN_EPOCHS_TO_INACTIVITY_PENALTY = 4,

    // State vector lengths
    .EPOCHS_PER_HISTORICAL_VECTOR = 65536,
    .EPOCHS_PER_SLASHINGS_VECTOR = 8192,
    .HISTORICAL_ROOTS_LIMIT = 16777216,
    .VALIDATOR_REGISTRY_LIMIT = 1099511627776,

    // Reward and penalty quotients
    .BASE_REWARD_FACTOR = 64,
    .WHISTLEBLOWER_REWARD_QUOTIENT = 512,
    .PROPOSER_REWARD_QUOTIENT = 8,
    .INACTIVITY_PENALTY_QUOTIENT = 67108864,
    .MIN_SLASHING_PENALTY_QUOTIENT = 128,
    .PROPORTIONAL_SLASHING_MULTIPLIER = 1,

    // Max operations per block
    .MAX_PROPOSER_SLASHINGS = 16,
    .MAX_ATTESTER_SLASHINGS = 2,
    .MAX_ATTESTATIONS = 128,
    .MAX_DEPOSITS = 16,
    .MAX_VOLUNTARY_EXITS = 16,

    // ALTAIR
    .SYNC_COMMITTEE_SIZE = 512,
    .EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256,
    .INACTIVITY_PENALTY_QUOTIENT_ALTAIR = 50331648,
    .MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR = 64,
    .PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR = 2,
    .MIN_SYNC_COMMITTEE_PARTICIPANTS = 1,
    .UPDATE_TIMEOUT = 8192,

    // BELLATRIX
    .INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = 16777216,
    .MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX = 32,
    .PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = 3,
    .MAX_BYTES_PER_TRANSACTION = 1073741824,
    .MAX_TRANSACTIONS_PER_PAYLOAD = 1048576,
    .BYTES_PER_LOGS_BLOOM = 256,
    .MAX_EXTRA_DATA_BYTES = 32,

    // CAPELLA
    .MAX_BLS_TO_EXECUTION_CHANGES = 16,
    .MAX_WITHDRAWALS_PER_PAYLOAD = 16,
    .MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP = 16384,

    // DENEB
    .FIELD_ELEMENTS_PER_BLOB = 4096,
    .MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096,
    .MAX_BLOBS_PER_BLOCK = 6,
    .KZG_COMMITMENT_INCLUSION_PROOF_DEPTH = 17,

    // ELECTRA
    .MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = 8192,
    .MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = 16,
    .MAX_ATTESTER_SLASHINGS_ELECTRA = 1,
    .MAX_ATTESTATIONS_ELECTRA = 8,
    .MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP = 8,
    .MAX_EFFECTIVE_BALANCE_ELECTRA = 2048000000000,
    .MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA = 4096,
    .MIN_ACTIVATION_BALANCE = 32000000000,
    .PENDING_BALANCE_DEPOSITS_LIMIT = 134217728,
    .PENDING_PARTIAL_WITHDRAWALS_LIMIT = 134217728,
    .PENDING_CONSOLIDATIONS_LIMIT = 262144,
    .MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = 1,
    .WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA = 4096,
};

/// Minimal preset for testing
/// https://github.com/ethereum/consensus-specs/tree/dev/presets/minimal
pub const minimal_preset = BeaconPreset{
    // Misc
    .MAX_COMMITTEES_PER_SLOT = 4,
    .TARGET_COMMITTEE_SIZE = 4,
    .MAX_VALIDATORS_PER_COMMITTEE = 2048,

    .SHUFFLE_ROUND_COUNT = 10,

    .HYSTERESIS_QUOTIENT = 4,
    .HYSTERESIS_DOWNWARD_MULTIPLIER = 1,
    .HYSTERESIS_UPWARD_MULTIPLIER = 5,

    // Gwei Values
    .MIN_DEPOSIT_AMOUNT = 1000000000,
    .MAX_EFFECTIVE_BALANCE = 32000000000,
    .EFFECTIVE_BALANCE_INCREMENT = 1000000000,

    // Time parameters
    .MIN_ATTESTATION_INCLUSION_DELAY = 1,
    .SLOTS_PER_EPOCH = 8,
    .MIN_SEED_LOOKAHEAD = 1,
    .MAX_SEED_LOOKAHEAD = 4,
    .EPOCHS_PER_ETH1_VOTING_PERIOD = 4,
    .SLOTS_PER_HISTORICAL_ROOT = 64,
    .MIN_EPOCHS_TO_INACTIVITY_PENALTY = 4,

    // State vector lengths
    .EPOCHS_PER_HISTORICAL_VECTOR = 64,
    .EPOCHS_PER_SLASHINGS_VECTOR = 64,
    .HISTORICAL_ROOTS_LIMIT = 16777216,
    .VALIDATOR_REGISTRY_LIMIT = 1099511627776,

    // Reward and penalty quotients
    .BASE_REWARD_FACTOR = 64,
    .WHISTLEBLOWER_REWARD_QUOTIENT = 512,
    .PROPOSER_REWARD_QUOTIENT = 8,
    .INACTIVITY_PENALTY_QUOTIENT = 33554432,
    .MIN_SLASHING_PENALTY_QUOTIENT = 64,
    .PROPORTIONAL_SLASHING_MULTIPLIER = 2,

    // Max operations per block
    .MAX_PROPOSER_SLASHINGS = 16,
    .MAX_ATTESTER_SLASHINGS = 2,
    .MAX_ATTESTATIONS = 128,
    .MAX_DEPOSITS = 16,
    .MAX_VOLUNTARY_EXITS = 16,

    // ALTAIR
    .SYNC_COMMITTEE_SIZE = 32,
    .EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 8,
    .INACTIVITY_PENALTY_QUOTIENT_ALTAIR = 50331648,
    .MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR = 64,
    .PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR = 2,
    .MIN_SYNC_COMMITTEE_PARTICIPANTS = 1,
    .UPDATE_TIMEOUT = 64,

    // BELLATRIX
    .INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = 16777216,
    .MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX = 32,
    .PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = 3,
    .MAX_BYTES_PER_TRANSACTION = 1073741824,
    .MAX_TRANSACTIONS_PER_PAYLOAD = 1048576,
    .BYTES_PER_LOGS_BLOOM = 256,
    .MAX_EXTRA_DATA_BYTES = 32,

    // CAPELLA
    .MAX_BLS_TO_EXECUTION_CHANGES = 16,
    .MAX_WITHDRAWALS_PER_PAYLOAD = 4,
    .MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP = 16,

    // DENEB
    .FIELD_ELEMENTS_PER_BLOB = 4096,
    .MAX_BLOB_COMMITMENTS_PER_BLOCK = 16,
    .MAX_BLOBS_PER_BLOCK = 6,
    .KZG_COMMITMENT_INCLUSION_PROOF_DEPTH = 9,
    // ELECTRA
    .MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = 4,
    .MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = 2,
    .MAX_ATTESTER_SLASHINGS_ELECTRA = 1,
    .MAX_ATTESTATIONS_ELECTRA = 8,
    .MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP = 1,
    .MAX_EFFECTIVE_BALANCE_ELECTRA = 2048000000000,
    .MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA = 4096,
    .MIN_ACTIVATION_BALANCE = 32000000000,
    .PENDING_BALANCE_DEPOSITS_LIMIT = 134217728,
    .PENDING_PARTIAL_WITHDRAWALS_LIMIT = 64,
    .PENDING_CONSOLIDATIONS_LIMIT = 64,
    .MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = 1,
    .WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA = 4096,
};

test "mainnet preset" {
    try std.testing.expectEqual(mainnet_preset.MAX_BYTES_PER_TRANSACTION, 1073741824);
    try std.testing.expectEqual(mainnet_preset.MAX_TRANSACTIONS_PER_PAYLOAD, 1048576);
    try std.testing.expectEqual(mainnet_preset.BYTES_PER_LOGS_BLOOM, 256);
    try std.testing.expectEqual(mainnet_preset.MAX_EXTRA_DATA_BYTES, 32);
    try std.testing.expectEqual(mainnet_preset.MAX_BLS_TO_EXECUTION_CHANGES, 16);
    try std.testing.expectEqual(mainnet_preset.MAX_WITHDRAWALS_PER_PAYLOAD, 16);
    try std.testing.expectEqual(mainnet_preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP, 16384);
    try std.testing.expectEqual(mainnet_preset.FIELD_ELEMENTS_PER_BLOB, 4096);
    try std.testing.expectEqual(mainnet_preset.MAX_BLOB_COMMITMENTS_PER_BLOCK, 4096);
    try std.testing.expectEqual(mainnet_preset.MAX_BLOBS_PER_BLOCK, 6);
    try std.testing.expectEqual(mainnet_preset.KZG_COMMITMENT_INCLUSION_PROOF_DEPTH, 17);
    try std.testing.expectEqual(mainnet_preset.MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, 8192);
    try std.testing.expectEqual(mainnet_preset.MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD, 16);
    try std.testing.expectEqual(mainnet_preset.MAX_ATTESTER_SLASHINGS_ELECTRA, 1);
    try std.testing.expectEqual(mainnet_preset.MAX_ATTESTATIONS_ELECTRA, 8);
    try std.testing.expectEqual(mainnet_preset.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP, 8);
    try std.testing.expectEqual(mainnet_preset.MAX_EFFECTIVE_BALANCE_ELECTRA, 2048000000000);
    try std.testing.expectEqual(mainnet_preset.MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA, 4096);
}

test "minimal preset" {
    try std.testing.expectEqual(minimal_preset.MAX_BYTES_PER_TRANSACTION, 1073741824);
    try std.testing.expectEqual(minimal_preset.MAX_TRANSACTIONS_PER_PAYLOAD, 1048576);
    try std.testing.expectEqual(minimal_preset.BYTES_PER_LOGS_BLOOM, 256);
    try std.testing.expectEqual(minimal_preset.MAX_EXTRA_DATA_BYTES, 32);
    try std.testing.expectEqual(minimal_preset.MAX_BLS_TO_EXECUTION_CHANGES, 16);
    try std.testing.expectEqual(minimal_preset.MAX_WITHDRAWALS_PER_PAYLOAD, 4);
    try std.testing.expectEqual(minimal_preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP, 16);
    try std.testing.expectEqual(minimal_preset.FIELD_ELEMENTS_PER_BLOB, 4096);
    try std.testing.expectEqual(minimal_preset.MAX_BLOB_COMMITMENTS_PER_BLOCK, 16);
    try std.testing.expectEqual(minimal_preset.MAX_BLOBS_PER_BLOCK, 6);
    try std.testing.expectEqual(minimal_preset.KZG_COMMITMENT_INCLUSION_PROOF_DEPTH, 9);
    try std.testing.expectEqual(minimal_preset.MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, 4);
    try std.testing.expectEqual(minimal_preset.MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD, 2);
    try std.testing.expectEqual(minimal_preset.MAX_ATTESTER_SLASHINGS_ELECTRA, 1);
    try std.testing.expectEqual(minimal_preset.MAX_ATTESTATIONS_ELECTRA, 8);
    try std.testing.expectEqual(minimal_preset.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP, 1);
    try std.testing.expectEqual(minimal_preset.MAX_EFFECTIVE_BALANCE_ELECTRA, 2048000000000);
    try std.testing.expectEqual(minimal_preset.MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA, 4096);
    try std.testing.expectEqual(minimal_preset.MIN_ACTIVATION_BALANCE, 32000000000);
}

test "test ActivePreset" {
    ActivePreset.set(Presets.mainnet);
    defer ActivePreset.reset();
    const active_preset = ActivePreset.get();
    try std.testing.expectEqual(active_preset.MAX_BYTES_PER_TRANSACTION, 1073741824);
}
