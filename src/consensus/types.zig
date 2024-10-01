const std = @import("std");
const primitives = @import("../primitives/types.zig");
const preset = @import("../presets/preset.zig");
const constants = @import("../primitives/constants.zig");
const bellatrix = @import("../consensus/bellatrix/types.zig");
const capella = @import("../consensus/capella/types.zig");
const deneb = @import("../consensus/deneb/types.zig");
const electra = @import("../consensus/electra/types.zig");

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

pub const IndexedAttestation = struct {
    attesting_indices: []primitives.ValidatorIndex,
    data: ?*AttestationData,
    signature: primitives.BLSSignature,
};

pub const PendingAttestation = struct {
    aggregation_bits: std.DynamicBitSet,
    data: AttestationData,
    inclusion_delay: primitives.Slot,
    proposer_index: primitives.ValidatorIndex,
};

pub const Eth1Data = struct {
    deposit_root: primitives.Root,
    deposit_count: u64,
    block_hash: primitives.Hash32,
};

pub fn HistoricalBatchType(comptime T: preset.BeaconPreset) type {
    return struct {
        block_roots: [T.SLOTS_PER_HISTORICAL_ROOT]primitives.Root,
        state_roots: [T.SLOTS_PER_HISTORICAL_ROOT]primitives.Root,
    };
}

pub const HistoricalBatchMainnet = HistoricalBatchType(preset.mainnet_preset);
pub const HistoricalBatchMininal = HistoricalBatchType(preset.minimal_preset);

pub const HistoricalBatch = struct {
    block_roots: []primitives.Root,
    state_roots: []primitives.Root,
};

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

pub const AttesterSlashing = struct {
    attestation_1: ?*IndexedAttestation,
    attestation_2: ?*IndexedAttestation,
};

pub const Attestation = struct {
    aggregation_bits: std.DynamicBitSet,
    data: ?*AttestationData,
    signature: primitives.BLSSignature,
    committee_bits: std.DynamicBitSet,
};

pub const Deposit = struct {
    proof: [constants.DEPOSIT_CONTRACT_TREE_DEPTH + 1]primitives.Bytes32,
    data: ?*DepositData,
};

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

pub const AggregateAndProof = struct {
    aggregator_index: primitives.ValidatorIndex,
    aggregate: ?*Attestation,
    selection_proof: primitives.BLSSignature,
};

pub const SyncAggregate = struct {
    sync_committee_bits: std.DynamicBitSet,
    sync_committee_signature: primitives.BLSSignature,
};

pub const SyncCommittee = struct {
    pubkeys: []primitives.BLSPubkey,
    aggregate_pubkey: primitives.BLSPubkey,
};

pub const SyncCommitteeMessage = struct {
    slot: primitives.Slot,
    beacon_block_root: primitives.Root,
    validator_index: primitives.ValidatorIndex,
    signature: primitives.BLSSignature,
};

pub const SyncCommitteeContribution = struct {
    slot: primitives.Slot,
    beacon_block_root: primitives.Root,
    subcommittee_index: u64,
    aggregation_bits: std.DynamicBitSet,
    signature: primitives.BLSSignature,
};

pub const ContributionAndProof = struct {
    aggregator_index: primitives.ValidatorIndex,
    aggregate: ?*SyncCommitteeContribution,
    selection_proof: primitives.BLSSignature,
};

pub const SignedBeaconBlock = struct {
    message: ?*ContributionAndProof,
    signature: primitives.BLSSignature,
};

pub const SyncAggregatorSelectionData = struct {
    slot: primitives.Slot,
    subcommittee_index: u64,
};

pub const ExecutionPayloadHeader = union(primitives.ForkType) {
    phase0: type,
    altair: type,
    bellatrix: bellatrix.ExecutionPayloadHeader,
    capella: capella.ExecutionPayloadHeader,
    deneb: deneb.ExecutionPayloadHeader,
    electra: electra.ExecutionPayloadHeader,
};

pub const LightClientHeader = struct {
    beacon: ?*BeaconBlockHeader,
    execution: ?*ExecutionPayloadHeader,
    execution_branch: primitives.ExecutionBranch,
};

pub const LightClientOptimisticUpdate = struct {
    attested_header: ?*LightClientHeader,
    sync_aggregate: ?*SyncAggregate,
    signature_slot: primitives.Slot,
};

pub const LightClientFinalityUpdate = struct {
    attested_header: ?*LightClientHeader,
    finalized_header: ?*LightClientHeader,
    finality_branch: primitives.FinalityBranch,
    sync_aggregate: ?*SyncAggregate,
    signature_slot: primitives.Slot,
};

pub const LightClientUpdate = struct {
    attested_header: ?*LightClientHeader,
    next_sync_committee: ?*SyncCommittee,
    next_sync_committee_branch: primitives.NextSyncCommitteeBranch,
    finalized_header: ?*LightClientHeader,
    finality_branch: primitives.FinalityBranch,
    sync_aggregate: ?*SyncAggregate,
    signature_slot: primitives.Slot,
};

pub const LightClientBootstrap = struct {
    header: ?*LightClientHeader,
    current_sync_committee: ?*SyncCommittee,
    current_sync_committee_branch: primitives.CurrentSyncCommitteeBranch,
};

pub const PowBlock = struct {
    block_hash: primitives.Hash32,
    parent_hash: primitives.Hash32,
    total_difficulty: u256,
};

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
    message: ?*BLSToExecutionChange,
    signature: primitives.BLSSignature,
};

pub const HistoricalSummary = struct {
    // HistoricalSummary matches the components of the phase0 HistoricalBatch
    // making the two hash_tree_root-compatible.
    block_summary_root: primitives.Root,
    state_summary_root: primitives.Root,
};

pub const BlobSidecar = struct {
    index: primitives.BlobIndex,
    blob: primitives.Blob,
    kzg_commitment: primitives.KZGCommitment,
    kzg_proof: primitives.KZGProof,
    signed_block_header: ?*SignedBeaconBlockHeader,
    kzg_commitment_inclusion_proof: []primitives.Bytes32,
};

pub const BlobIdentifier = struct {
    block_root: primitives.Root,
    index: primitives.BlobIndex,
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
