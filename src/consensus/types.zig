const std = @import("std");
const primitives = @import("../primitives/types.zig");
const preset = @import("../presets/preset.zig");

pub const Fork = struct {
    previous_version: primitives.Version,
    current_version: primitives.Version,
    epoch: primitives.Epoch,
};

pub const ForkData = struct {
    current_version: primitives.Version,
    genesis_validators_root: primitives.Root,
};

pub const Checkpoint = struct {
    epoch: primitives.Epoch,
    root: primitives.Root,
};

pub const Validator = struct {
    pubkey: primitives.BLSPubkey,
    withdrawal_credentials: primitives.Bytes32,
    effective_balance: primitives.Gwei,
    slashed: bool,
    activation_eligibility_epoch: primitives.Epoch,
    activation_epoch: primitives.Epoch,
    exit_epoch: primitives.Epoch,
    withdrawable_epoch: primitives.Epoch,
};

pub const AttestationData = struct {
    slot: primitives.Slot,
    index: primitives.CommitteeIndex,
    // LMD GHOST vote
    beacon_block_root: primitives.Root,
    // FFG vote
    source: ?*Checkpoint,
    target: ?*Checkpoint,
};

pub fn IndexedAttestation(comptime T: preset.BeaconPreset) type {
    return struct {
        attesting_indices: [T.MAX_VALIDATORS_PER_COMMITTEE * T.MAX_COMMITTEES_PER_SLOT]primitives.ValidatorIndex,
        data: ?*AttestationData,
        signature: primitives.BLSSignature,
    };
}

pub fn PendingAttestation(comptime T: preset.BeaconPreset) type {
    return struct {
        aggregation_bits: std.StaticBitSet(T.MAX_VALIDATORS_PER_COMMITTEE),
        data: AttestationData,
        inclusion_delay: primitives.Slot,
        proposer_index: primitives.ValidatorIndex,
    };
}

pub const Eth1Data = struct {
    deposit_root: primitives.Root,
    deposit_count: u64,
    block_hash: primitives.Hash32,
};

pub fn HistoricalBatch(comptime T: preset.BeaconPreset) type {
    return struct {
        block_roots: [T.SLOTS_PER_HISTORICAL_ROOT]primitives.Root,
        state_roots: [T.SLOTS_PER_HISTORICAL_ROOT]primitives.Root,
    };
}

pub const DepositMessage = struct {
    pubkey: primitives.BLSPubkey,
    withdrawal_credentials: primitives.Bytes32,
    amount: primitives.Gwei,
};

pub const DepositData = struct {
    pubkey: primitives.BLSPubkey,
    withdrawal_credentials: primitives.Bytes32,
    amount: primitives.Gwei,
    signature: primitives.BLSSignature,
};

pub const BeaconBlockHeader = struct {
    slot: primitives.Slot,
    proposer_index: primitives.ValidatorIndex,
    parent_root: primitives.Root,
    state_root: primitives.Root,
    body_root: primitives.Root,
};

pub const SigningData = struct {
    object_root: primitives.Root,
    domain: primitives.Domain,
};

pub fn AttesterSlashing(comptime T: preset.BeaconPreset) type {
    return struct {
        attestation_1: ?*IndexedAttestation(T),
        attestation_2: ?*IndexedAttestation(T),
    };
}

pub fn Attestation(comptime T: preset.BeaconPreset) type {
    return struct {
        aggregation_bits: std.StaticBitSet(T.MAX_VALIDATORS_PER_COMMITTEE),
        data: ?*AttestationData,
        signature: primitives.BLSSignature,
        committee_bits: std.StaticBitSet(T.MAX_COMMITTEES_PER_SLOT),
    };
}

pub fn Deposit(comptime T: preset.BeaconPreset) type {
    return struct {
        proof: [T.DEPOSIT_CONTRACT_TREE_DEPTH + 1]primitives.Bytes32,
        data: ?*DepositData,
    };
}

pub const VoluntaryExit = struct {
    epoch: primitives.Epoch,
    validator_index: primitives.ValidatorIndex,
};

pub const SignedVoluntaryExit = struct {
    message: ?*VoluntaryExit,
    signature: primitives.BLSSignature,
};

pub const SignedBeaconBlockHeader = struct {
    message: ?*BeaconBlockHeader,
    signature: primitives.BLSSignature,
};

pub const ProposerSlashing = struct {
    signed_header_1: ?*SignedBeaconBlockHeader,
    signed_header_2: ?*SignedBeaconBlockHeader,
};

pub const Eth1Block = struct {
    timestamp: u64,
    deposit_root: primitives.Root,
    deposit_count: u64,
};

pub fn AggregateAndProof(comptime T: preset.BeaconPreset) type {
    return struct {
        aggregator_index: primitives.ValidatorIndex,
        aggregate: ?*Attestation(T),
        selection_proof: primitives.BLSSignature,
    };
}

pub fn SyncAggregate(comptime T: preset.BeaconPreset) type {
    return struct {
        sync_committee_bits: std.StaticBitSet(T.SYNC_COMMITTEE_SIZE),
        sync_committee_signature: primitives.BLSSignature,
    };
}

pub fn SyncCommittee(comptime T: preset.BeaconPreset) type {
    return struct {
        pubkeys: [T.SYNC_COMMITTEE_SIZE]primitives.BLSPubkey,
        aggregate_pubkey: primitives.BLSPubkey,
    };
}

pub const SyncCommitteeMessage = struct {
    slot: primitives.Slot,
    beacon_block_root: primitives.Root,
    validator_index: primitives.ValidatorIndex,
    signature: primitives.BLSSignature,
};

pub fn SyncCommitteeContribution(comptime T: preset.BeaconPreset) type {
    return struct {
        slot: primitives.Slot,
        beacon_block_root: primitives.Root,
        subcommittee_index: u64,
        aggregation_bits: std.StaticBitSet(T.SYNC_COMMITTEE_SIZE / T.SYNC_COMMITTEE_SUBNET_COUNT),
        signature: primitives.BLSSignature,
    };
}

pub fn ContributionAndProof(comptime T: preset.BeaconPreset) type {
    return struct {
        aggregator_index: primitives.ValidatorIndex,
        aggregate: ?*SyncCommitteeContribution(T),
        selection_proof: primitives.BLSSignature,
    };
}

pub fn SignedBeaconBlock(comptime T: preset.BeaconPreset) type {
    return struct {
        message: ?*ContributionAndProof(T),
        signature: primitives.BLSSignature,
    };
}

pub const SyncAggregatorSelectionData = struct {
    slot: primitives.Slot,
    subcommittee_index: u64,
};

pub fn ExecutionPayloadHeader(comptime T: preset.BeaconPreset) type {
    return struct {
        // Execution block header fields
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
        blob_gas_used: u64,
        excess_blob_gas: u64,
        deposit_requests_root: primitives.Root,
        withdrawal_requests_root: primitives.Root,
        consolidation_requests_root: primitives.Root,
    };
}

pub fn LightClientHeader(comptime T: preset.BeaconPreset) type {
    return struct {
        beacon: ?*BeaconBlockHeader,
        execution: ?*ExecutionPayloadHeader(T),
        execution_branch: primitives.ExecutionBranch,
    };
}

pub fn LightClientOptimisticUpdate(comptime T: preset.BeaconPreset) type {
    return struct {
        attested_header: ?*LightClientHeader(T),
        sync_aggregate: ?*SyncAggregate(T),
        signature_slot: primitives.Slot,
    };
}

pub fn LightClientFinalityUpdate(comptime T: preset.BeaconPreset) type {
    return struct {
        attested_header: ?*LightClientHeader(T),
        finalized_header: ?*LightClientHeader(T),
        finality_branch: primitives.Slot,
        sync_aggregate: ?*SyncAggregate(T),
        signature_slot: primitives.Slot,
    };
}

// pub const BeaconState = struct {
//     genesis_time: u64,
//     genesis_validators_root: Root,
//     slot: Slot,
//     fork: Fork,
//     latest_block_header: BeaconBlockHeader,
//     block_roots: [SLOTS_PER_HISTORICAL_ROOT]Root,
//     state_roots: [SLOTS_PER_HISTORICAL_ROOT]Root,
//     historical_roots: std.ArrayList(Root),
//     eth1_data: Eth1Data,
//     eth1_data_votes: std.ArrayList(Eth1Data),
//     eth1_deposit_index: u64,
//     validators: std.ArrayList(Validator),
//     balances: std.ArrayList(Gwei),
//     randao_mixes: [EPOCHS_PER_HISTORICAL_VECTOR][32]u8,
//     slashings: [EPOCHS_PER_SLASHINGS_VECTOR]Gwei,
//     previous_epoch_participation: std.ArrayList(ParticipationFlags),
//     current_epoch_participation: std.ArrayList(ParticipationFlags),
//     justification_bits: [JUSTIFICATION_BITS_LENGTH]bool,
//     previous_justified_checkpoint: Checkpoint,
//     current_justified_checkpoint: Checkpoint,
//     finalized_checkpoint: Checkpoint,
//     inactivity_scores: std.ArrayList(u64),
//     current_sync_committee: SyncCommittee,
//     next_sync_committee: SyncCommittee,
//     latest_execution_payload_header: ExecutionPayloadHeader,
//     next_withdrawal_index: WithdrawalIndex,
//     next_withdrawal_validator_index: ValidatorIndex,
//     historical_summaries: std.ArrayList(HistoricalSummary),
//     deposit_requests_start_index: u64,
//     deposit_balance_to_consume: Gwei,
//     exit_balance_to_consume: Gwei,
//     earliest_exit_epoch: Epoch,
//     consolidation_balance_to_consume: Gwei,
//     earliest_consolidation_epoch: Epoch,
//     pending_balance_deposits: std.ArrayList(PendingBalanceDeposit),
//     pending_partial_withdrawals: std.ArrayList(PendingPartialWithdrawal),
//     pending_consolidations: std.ArrayList(PendingConsolidation),
// };
