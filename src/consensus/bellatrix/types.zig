const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");
const altair = @import("../../consensus/altair/types.zig");

pub const PowBlock = struct {
    block_hash: primitives.Hash32,
    parent_hash: primitives.Hash32,
    total_difficulty: u256,
};

pub const ExecutionPayloadHeader = struct {
    parent_hash: primitives.Hash32,
    fee_recipient: primitives.ExecutionAddress,
    state_root: primitives.Root,
    receipts_root: primitives.Root,
    logs_bloom: []u8,
    prev_randao: primitives.Bytes32,
    block_number: u64,
    gas_used: u64,
    gas_limit: u64,
    timestamp: u64,
    extra_data: []u8,
    base_fee_per_gas: u256,
    // Extra payload fields
    block_hash: primitives.Hash32,
    transactions_root: primitives.Root,
};

pub const ExecutionPayload = struct {
    // Execution block header fields
    parent_hash: primitives.Hash32,
    fee_recipient: primitives.ExecutionAddress, // 'beneficiary' in the yellow paper
    state_root: primitives.Bytes32,
    receipts_root: primitives.Bytes32,
    logs_bloom: []u8,
    prev_randao: primitives.Bytes32, // 'difficulty' in the yellow paper
    block_number: u64, // 'number' in the yellow paper
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []u8, // with a maximum length of MAX_EXTRA_DATA_BYTES
    base_fee_per_gas: u256,
    // Extra payload fields
    block_hash: primitives.Hash32, // Hash of execution block
    transactions: []primitives.Transaction, // with a maximum length of MAX_TRANSACTIONS_PER_PAYLOAD
};

pub const BeaconBlockBody = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(altair.BeaconBlockBody).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "execution_payload",
                    .type = ?*consensus.ExecutionPayload,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(?*consensus.ExecutionPayload),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const BeaconState = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(altair.BeaconState).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "latest_execution_payload_header",
                    .type = ?*consensus.ExecutionPayloadHeader,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(?*consensus.ExecutionPayloadHeader),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

test "test ExecutionPayloadHeader" {
    const header = ExecutionPayloadHeader{
        .parent_hash = undefined,
        .fee_recipient = undefined,
        .state_root = undefined,
        .receipts_root = undefined,
        .logs_bloom = undefined,
        .prev_randao = undefined,
        .block_number = 21,
        .gas_used = 0,
        .gas_limit = 0,
        .timestamp = 0,
        .extra_data = undefined,
        .base_fee_per_gas = 0,
        .block_hash = undefined,
        .transactions_root = undefined,
    };

    try std.testing.expectEqual(header.parent_hash.len, 32);
    try std.testing.expectEqual(header.block_number, 21);
}

test "test ExecutionPayload" {
    const payload = ExecutionPayload{
        .parent_hash = undefined,
        .fee_recipient = undefined,
        .state_root = undefined,
        .receipts_root = undefined,
        .logs_bloom = undefined,
        .prev_randao = undefined,
        .block_number = 21,
        .gas_used = 0,
        .gas_limit = 0,
        .timestamp = 0,
        .extra_data = undefined,
        .base_fee_per_gas = 0,
        .block_hash = undefined,
        .transactions = &[_]primitives.Transaction{},
    };

    try std.testing.expectEqual(payload.block_number, 21);
}

test "test BeaconBlockBody" {
    const body = BeaconBlockBody{
        .randao_reveal = undefined,
        .eth1_data = undefined,
        .graffiti = undefined,
        .proposer_slashings = undefined,
        .attester_slashings = undefined,
        .attestations = undefined,
        .deposits = undefined,
        .voluntary_exits = undefined,
        .sync_aggregate = undefined,
        .execution_payload = undefined,
    };

    try std.testing.expectEqual(body.randao_reveal.len, 96);
}

test "test BeaconState" {
    const state = BeaconState{
        .genesis_time = 0,
        .genesis_validators_root = undefined,
        .slot = 0,
        .fork = undefined,
        .latest_block_header = undefined,
        .block_roots = undefined,
        .state_roots = undefined,
        .historical_roots = undefined,
        .eth1_data = undefined,
        .eth1_data_votes = undefined,
        .eth1_deposit_index = 0,
        .validators = undefined,
        .balances = undefined,
        .randao_mixes = undefined,
        .slashings = undefined,
        .previous_epoch_attestations = undefined,
        .current_epoch_attestations = undefined,
        .justification_bits = undefined,
        .previous_justified_checkpoint = undefined,
        .current_justified_checkpoint = undefined,
        .finalized_checkpoint = undefined,
        .inactivity_scores = undefined,
        .current_sync_committee = undefined,
        .next_sync_committee = undefined,
        .latest_execution_payload_header = undefined,
    };

    try std.testing.expectEqual(state.genesis_time, 0);
}

test "test PowBlock" {
    const block = PowBlock{
        .block_hash = undefined,
        .parent_hash = undefined,
        .total_difficulty = 0,
    };

    try std.testing.expectEqual(block.block_hash.len, 32);
    try std.testing.expectEqual(block.total_difficulty, 0);
}
