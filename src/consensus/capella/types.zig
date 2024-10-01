const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");

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
    withdrawals_root: primitives.Root,
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
    withdrawals: []consensus.Withdrawal, // with a maximum length of MAX_WITHDRAWALS_PER_PAYLOAD
};

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
        .withdrawals_root = undefined,
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
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = undefined,
        .base_fee_per_gas = 0,
        .block_hash = undefined,
        .transactions = undefined,
        .withdrawals = undefined,
    };

    try std.testing.expectEqual(payload.parent_hash.len, 32);
    try std.testing.expectEqual(payload.block_number, 21);
}
