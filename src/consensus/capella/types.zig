const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");

pub fn ExecutionPayloadHeaderType(comptime T: preset.BeaconPreset) type {
    return struct {
        parent_hash: primitives.Hash32,
        fee_recipient: primitives.ExecutionAddress,
        state_root: primitives.Root,
        receipts_root: primitives.Root,
        logs_bloom: [T.BYTES_PER_LOGS_BLOOM]u8,
        prev_randao: primitives.Bytes32,
        block_number: u64,
        gas_used: u64,
        gas_limit: u64,
        timestamp: u64,
        extra_data: [T.MAX_EXTRA_DATA_BYTES]u8,
        base_fee_per_gas: u256,
        // Extra payload fields
        block_hash: primitives.Hash32,
        transactions_root: primitives.Root,
        withdrawals_root: primitives.Root,
    };
}

pub const ExecutionPayloadHeaderMainnet = ExecutionPayloadHeaderType(preset.mainnet_preset);

pub const ExecutionPayloadHeaderMinimal = ExecutionPayloadHeaderType(preset.minimal_preset);

pub const ExecutionPayloadHeader = union(preset.Presets) {
    mainnet: ExecutionPayloadHeaderMainnet,
    minimal: ExecutionPayloadHeaderMinimal,
};

test "test ExecutionPayloadHeaderMainnet" {
    const header = ExecutionPayloadHeaderMainnet{
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
