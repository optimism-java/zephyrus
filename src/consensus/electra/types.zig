const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const deneb = @import("../../consensus/deneb/types.zig");
const capella = @import("../../consensus/capella/types.zig");

pub const PendingConsolidation = struct {
    source_index: primitives.ValidatorIndex,
    target_index: primitives.ValidatorIndex,
};

pub const DepositRequest = struct {
    pubkey: primitives.BLSPubkey,
    withdrawal_credentials: primitives.Bytes32,
    amount: primitives.Gwei,
    signature: primitives.BLSSignature,
    index: u64,
};

pub const PendingBalanceDeposit = struct {
    index: primitives.ValidatorIndex,
    amount: primitives.Gwei,
};

pub const PendingPartialWithdrawal = struct {
    index: primitives.ValidatorIndex,
    amount: primitives.Gwei,
    withdrawable_epoch: primitives.Epoch,
};

pub const WithdrawalRequest = struct {
    source_address: primitives.ExecutionAddress,
    validator_pubkey: primitives.BLSPubkey,
    amount: primitives.Gwei,
};

pub const ConsolidationRequest = struct {
    source_address: primitives.ExecutionAddress,
    source_pubkey: primitives.BLSPubkey,
    target_pubkey: primitives.BLSPubkey,
};

pub const Attestation = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(phase0.Attestation).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "committee_bits", // # [New in Electra:EIP7549]
                    .type = []bool,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]bool),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const ExecutionPayload = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(deneb.ExecutionPayload).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "deposit_requests", // # [New in Electra:EIP7002:EIP7251]
                    .type = []consensus.DepositRequest,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.DepositRequest),
                },
                .{
                    .name = "withdrawal_requests", // # [New in Electra:EIP7002:EIP7251]
                    .type = []consensus.WithdrawalRequest,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.WithdrawalRequest),
                },
                .{
                    .name = "consolidation_requests", // # [New in Electra:EIP7002:EIP7251]
                    .type = []consensus.ConsolidationRequest,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.ConsolidationRequest),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const ExecutionPayloadHeader = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(deneb.ExecutionPayloadHeader).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "deposit_requests_root", // # [New in Electra:EIP7002:EIP7251]
                    .type = primitives.Root,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Root),
                },
                .{
                    .name = "withdrawal_requests_root", // # [New in Electra:EIP7002:EIP7251]
                    .type = primitives.Root,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Root),
                },
                .{
                    .name = "consolidation_requests_root", // # [New in Electra:EIP7002:EIP7251]
                    .type = primitives.Root,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Root),
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
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .deposit_requests_root = undefined,
        .withdrawal_requests_root = undefined,
        .consolidation_requests_root = undefined,
    };

    try std.testing.expectEqual(header.parent_hash.len, 32);
    try std.testing.expectEqual(header.block_number, 21);
}

pub const BeaconState = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(capella.BeaconState).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "deposit_requests_start_index", // # [New in Electra:EIP6110]
                    .type = u64,
                    .default_value = @ptrCast(&@as(u64, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(u64),
                },
                .{
                    .name = "deposit_balance_to_consume", // # [New in Electra:EIP7251]
                    .type = primitives.Gwei,
                    .default_value = @ptrCast(&@as(primitives.Gwei, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Gwei),
                },
                .{
                    .name = "exit_balance_to_consume", // # [New in Electra:EIP7251]
                    .type = primitives.Gwei,
                    .default_value = @ptrCast(&@as(primitives.Gwei, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Gwei),
                },
                .{
                    .name = "earliest_exit_epoch", // # [New in Electra:EIP7251]
                    .type = primitives.Epoch,
                    .default_value = @ptrCast(&@as(primitives.Epoch, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Epoch),
                },
                .{
                    .name = "consolidation_balance_to_consume", // # [New in Electra:EIP7251]
                    .type = primitives.Gwei,
                    .default_value = @ptrCast(&@as(primitives.Gwei, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Gwei),
                },
                .{
                    .name = "earliest_consolidation_epoch", // # [New in Electra:EIP7251]
                    .type = primitives.Epoch,
                    .default_value = @ptrCast(&@as(primitives.Epoch, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(primitives.Epoch),
                },
                .{
                    .name = "pending_balance_deposits", // # [New in Electra:EIP7251]
                    .type = []consensus.PendingBalanceDeposit,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.PendingBalanceDeposit),
                },
                .{
                    .name = "pending_partial_withdrawals", // # [New in Electra:EIP7251]
                    .type = []consensus.PendingPartialWithdrawal,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.PendingPartialWithdrawal),
                },
                .{
                    .name = "pending_consolidations", // # [New in Electra:EIP7251]
                    .type = []consensus.PendingConsolidation,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]consensus.PendingConsolidation),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

test "test Attestation" {
    const attestation = Attestation{
        .aggregation_bits = &[_]bool{},
        .data = undefined,
        .signature = undefined,
        .committee_bits = &[_]bool{},
    };

    try std.testing.expectEqual(attestation.aggregation_bits.len, 0);
    try std.testing.expectEqual(attestation.committee_bits.len, 0);
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
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .deposit_requests = undefined,
        .withdrawal_requests = undefined,
        .consolidation_requests = undefined,
    };

    try std.testing.expectEqual(payload.parent_hash.len, 32);
    try std.testing.expectEqual(payload.block_number, 21);
}

test "test DepositRequest" {
    const request = DepositRequest{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .amount = 0,
        .signature = undefined,
        .index = 0,
    };

    try std.testing.expectEqual(request.index, 0);
}

test "test PendingBalanceDeposit" {
    const deposit = PendingBalanceDeposit{
        .index = 0,
        .amount = 0,
    };

    try std.testing.expectEqual(deposit.index, 0);
}

test "test PendingPartialWithdrawal" {
    const withdrawal = PendingPartialWithdrawal{
        .index = 0,
        .amount = 0,
        .withdrawable_epoch = 0,
    };

    try std.testing.expectEqual(withdrawal.index, 0);
}

test "test WithdrawalRequest" {
    const request = WithdrawalRequest{
        .source_address = undefined,
        .validator_pubkey = undefined,
        .amount = 0,
    };

    try std.testing.expectEqual(request.amount, 0);
}

test "test ConsolidationRequest" {
    const request = ConsolidationRequest{
        .source_address = undefined,
        .source_pubkey = undefined,
        .target_pubkey = undefined,
    };

    try std.testing.expectEqual(request.source_address.len, 20);
}

test "test PendingConsolidation" {
    const consolidation = PendingConsolidation{
        .source_index = 0,
        .target_index = 0,
    };

    try std.testing.expectEqual(consolidation.source_index, 0);
}
