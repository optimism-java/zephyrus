const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");

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

pub const Attestation = struct {
    aggregation_bits: []bool, // # [Modified in Electra:EIP7549]
    data: ?*consensus.AttestationData,
    signature: primitives.BLSSignature,
    committee_bits: []bool, // # [New in Electra:EIP7549]
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
    blob_gas_used: u64,
    excess_blob_gas: u64,
    deposit_requests: []consensus.DepositRequest, // with a maximum length of MAX_DEPOSIT_REQUESTS_PER_PAYLOAD
    // # [New in Electra:EIP7002:EIP7251]
    withdrawal_requests: []consensus.WithdrawalRequest, // with a maximum length of MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
    // # [New in Electra:EIP7002:EIP7251]
    consolidation_requests: []consensus.ConsolidationRequest, // with a maximum length of MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
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
    withdrawals_root: primitives.Root,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    deposit_requests_root: primitives.Root,
    withdrawal_requests_root: primitives.Root,
    consolidation_requests_root: primitives.Root,
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
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .deposit_requests_root = undefined,
        .withdrawal_requests_root = undefined,
        .consolidation_requests_root = undefined,
    };

    try std.testing.expectEqual(header.parent_hash.len, 32);
    try std.testing.expectEqual(header.block_number, 21);
}

pub const BeaconState = struct {
    genesis_time: u64,
    genesis_validators_root: primitives.Root,
    slot: primitives.Slot,
    fork: *consensus.Fork,
    latest_block_header: consensus.BeaconBlockHeader,
    block_roots: []primitives.Root,
    state_roots: []primitives.Root,
    historical_roots: []primitives.Root,
    eth1_data: ?*consensus.Eth1Data,
    eth1_data_votes: []consensus.Eth1Data,
    eth1_deposit_index: u64,
    validators: []consensus.Validator,
    balances: []primitives.Gwei,
    randao_mixes: []primitives.Bytes32,
    slashings: []primitives.Gwei,
    previous_epoch_attestations: []consensus.PendingAttestation,
    current_epoch_attestations: []consensus.PendingAttestation,
    justification_bits: []bool,
    previous_justified_checkpoint: *consensus.Checkpoint,
    current_justified_checkpoint: *consensus.Checkpoint,
    finalized_checkpoint: *consensus.Checkpoint,
    inactivity_scores: []u64,
    current_sync_committee: ?*consensus.SyncCommittee,
    next_sync_committee: ?*consensus.SyncCommittee,
    latest_execution_payload_header: ?*consensus.ExecutionPayloadHeader,
    next_withdrawal_index: primitives.WithdrawalIndex,
    next_withdrawal_validator_index: primitives.ValidatorIndex,
    historical_summaries: []consensus.HistoricalSummary,
    deposit_requests_start_index: u64,
    deposit_balance_to_consume: primitives.Gwei,
    exit_balance_to_consume: primitives.Gwei,
    earliest_exit_epoch: primitives.Epoch,
    consolidation_balance_to_consume: primitives.Gwei,
    earliest_consolidation_epoch: primitives.Epoch,
    pending_balance_deposits: []consensus.PendingBalanceDeposit,
    pending_partial_withdrawals: []consensus.PendingPartialWithdrawal,
    pending_consolidations: []consensus.PendingConsolidation,
};

test "test Attestation" {
    const attestation = Attestation{
        .aggregation_bits = &[_]bool{},
        .data = undefined,
        .signature = undefined,
        .committee_bits = undefined,
    };

    try std.testing.expectEqual(attestation.aggregation_bits.len, 0);
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
