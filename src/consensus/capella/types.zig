const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");
const bellatrix = @import("../../consensus/bellatrix/types.zig");
const altair = @import("../../consensus/altair/types.zig");

pub const HistoricalSummary = struct {
    // HistoricalSummary matches the components of the phase0 HistoricalBatch
    // making the two hash_tree_root-compatible.
    block_summary_root: primitives.Root,
    state_summary_root: primitives.Root,
};

pub const LightClientHeader = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(altair.LightClientHeader).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "execution",
                    .type = consensus.ExecutionPayloadHeader,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(consensus.ExecutionPayloadHeader),
                },
                .{
                    .name = "execution_branch",
                    .type = primitives.ExecutionBranch,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.ExecutionBranch),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const Withdrawal = struct {
    index: primitives.WithdrawalIndex,
    validator_index: primitives.ValidatorIndex,
    address: primitives.ExecutionAddress,
    amount: primitives.Gwei,
};

pub const BLSToExecutionChange = struct {
    validator_index: primitives.ValidatorIndex,
    from_bls_pubkey: primitives.BLSPubkey,
    to_execution_address: primitives.ExecutionAddress,
};

pub const SignedBLSToExecutionChange = struct {
    message: consensus.BLSToExecutionChange,
    signature: primitives.BLSSignature,
};

pub const ExecutionPayloadHeader = @Type(.{
    .@"struct" = .{
        .layout = .auto,
        .fields = @typeInfo(bellatrix.ExecutionPayloadHeader).@"struct".fields ++ &[_]std.builtin.Type.StructField{
            .{
                .name = "withdrawals_root",
                .type = primitives.Root,
                .default_value = null,
                .is_comptime = false,
                .alignment = @alignOf(primitives.Root),
            },
        },
        .decls = &.{},
        .is_tuple = false,
    },
});

pub const ExecutionPayload = @Type(.{
    .@"struct" = .{
        .layout = .auto,
        .fields = @typeInfo(bellatrix.ExecutionPayload).@"struct".fields ++ &[_]std.builtin.Type.StructField{
            .{
                .name = "withdrawals",
                .type = []consensus.Withdrawal,
                .default_value = null,
                .is_comptime = false,
                .alignment = @alignOf([]consensus.Withdrawal),
            },
        },
        .decls = &.{},
        .is_tuple = false,
    },
});

pub const BeaconBlockBody = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(bellatrix.BeaconBlockBody).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "bls_to_execution_changes",
                    .type = []consensus.SignedBLSToExecutionChange,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.SignedBLSToExecutionChange),
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
            .fields = @typeInfo(bellatrix.BeaconState).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "next_withdrawal_index",
                    .type = primitives.WithdrawalIndex,
                    .default_value = &@as(primitives.WithdrawalIndex, 0),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.WithdrawalIndex),
                },
                .{
                    .name = "next_withdrawal_validator_index",
                    .type = primitives.ValidatorIndex,
                    .default_value = &@as(primitives.ValidatorIndex, 0),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.ValidatorIndex),
                },
                .{
                    .name = "historical_summaries",
                    .type = []consensus.HistoricalSummary,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.HistoricalSummary),
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
        .bls_to_execution_changes = undefined,
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
        .next_withdrawal_index = 0,
        .next_withdrawal_validator_index = 0,
        .historical_summaries = undefined,
        .previous_epoch_participation = undefined,
        .current_epoch_participation = undefined,
    };

    try std.testing.expectEqual(state.genesis_time, 0);
}

test "test LightClientHeader" {
    const header = LightClientHeader{
        .beacon = undefined,
        .execution = undefined,
        .execution_branch = undefined,
    };

    try std.testing.expectEqual(header.beacon, undefined);
    try std.testing.expectEqual(header.execution, undefined);
}

test "test Withdrawal" {
    const withdrawal = Withdrawal{
        .index = 0,
        .validator_index = 0,
        .address = undefined,
        .amount = 0,
    };

    try std.testing.expectEqual(withdrawal.index, 0);
}

test "test BLSToExecutionChange" {
    const change = BLSToExecutionChange{
        .validator_index = 0,
        .from_bls_pubkey = undefined,
        .to_execution_address = undefined,
    };

    try std.testing.expectEqual(change.validator_index, 0);
}

test "test SignedBLSToExecutionChange" {
    const change = SignedBLSToExecutionChange{
        .message = undefined,
        .signature = undefined,
    };

    try std.testing.expectEqual(change.message, undefined);
}

test "test HistoricalSummary" {
    const summary = HistoricalSummary{
        .block_summary_root = undefined,
        .state_summary_root = undefined,
    };

    try std.testing.expectEqual(summary.block_summary_root.len, 32);
}
