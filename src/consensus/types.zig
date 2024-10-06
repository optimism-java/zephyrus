const std = @import("std");
const primitives = @import("../primitives/types.zig");
const preset = @import("../presets/preset.zig");
const constants = @import("../primitives/constants.zig");
const phase0 = @import("../consensus/phase0/types.zig");
const altair = @import("../consensus/altair/types.zig");
const bellatrix = @import("../consensus/bellatrix/types.zig");
const capella = @import("../consensus/capella/types.zig");
const deneb = @import("../consensus/deneb/types.zig");
const electra = @import("../consensus/electra/types.zig");
const configs = @import("../configs/config.zig");
// const ssz = @import("../ssz/ssz.zig");

pub const NonExistType = struct {};

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

    /// Check if a validator is active at a given epoch.
    /// A validator is active if the current epoch is greater than or equal to the validator's activation epoch and less than the validator's exit epoch.
    /// @param epoch The epoch to check.
    /// @return True if the validator is active, false otherwise.
    /// Spec pseudocode definition:
    ///
    /// def is_active_validator(validator: Validator, epoch: Epoch) -> bool:
    /// """
    /// Check if ``validator`` is active.
    /// """
    ///    return validator.activation_epoch <= epoch < validator.exit_epoch
    pub fn isActiveValidator(self: *const Validator, epoch: primitives.Epoch) bool {
        return self.activation_epoch <= epoch and epoch < self.exit_epoch;
    }

    /// isEligibleForActivationQueue carries out the logic for IsEligibleForActivationQueue
    /// Spec pseudocode definition:
    ///
    /// def is_eligible_for_activation_queue(validator: Validator) -> bool:
    ///   """
    ///   Check if ``validator`` is eligible to be placed into the activation queue.
    ///   """
    ///   return (
    ///       validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
    ///       and validator.effective_balance == MAX_EFFECTIVE_BALANCE
    ///   )
    pub fn isEligibleForActivationQueue(self: *const Validator) bool {
        return self.activation_eligibility_epoch == constants.FAR_FUTURE_EPOCH and
            self.effective_balance == preset.ActivePreset.get().MIN_ACTIVATION_BALANCE;
    }

    /// isEligibleForActivation checks if a validator is eligible for activation.
    /// A validator is eligible for activation if it is not yet activated and its activation eligibility epoch is less than or equal to the finalized epoch.
    /// @param state The beacon state.
    /// @return True if the validator is eligible for activation, false otherwise.
    /// Spec pseudocode definition:
    ///
    /// def is_eligible_for_activation(state: BeaconState, validator: Validator) -> bool:
    ///   """
    ///   Check if ``validator`` is eligible for activation.
    ///   """
    ///   return (
    ///       validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
    ///       and validator.activation_epoch == FAR_FUTURE_EPOCH
    ///   )
    pub fn isEligibleForActivation(self: *const Validator, state: *const BeaconState) bool {
        return
        // Placement in queue is finalized
        self.activation_eligibility_epoch <= state.finalizedCheckpointEpoch() and
            // Has not yet been activated
            self.activation_epoch == constants.FAR_FUTURE_EPOCH;
    }

    /// isSlashableValidator checks if a validator is slashable.
    /// A validator is slashable if it is not yet slashed and is within the range of epochs where it can be withdrawn.
    /// @param epoch The epoch to check.
    /// @return True if the validator is slashable, false otherwise.
    /// Spec pseudocode definition:
    ///
    /// def is_slashable_validator(validator: Validator, epoch: Epoch) -> bool:
    ///     """
    ///    Check if ``validator`` is slashable.
    ///    """
    ///    return not validator.slashed and validator.activation_epoch <= epoch < validator.withdrawable_epoch
    pub fn isSlashableValidator(self: *const Validator, epoch: primitives.Epoch) bool {
        return (!self.slashed) and (self.activation_epoch <= epoch and epoch < self.withdrawable_epoch);
    }
};

pub const AttestationData = struct {
    slot: primitives.Slot,
    index: primitives.CommitteeIndex,
    // LMD GHOST vote
    beacon_block_root: primitives.Root,
    // FFG vote
    source: Checkpoint,
    target: Checkpoint,
};

pub const IndexedAttestation = struct {
    // # [Modified in Electra:EIP7549] size: MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT
    attesting_indices: []primitives.ValidatorIndex,
    data: ?*AttestationData,
    signature: primitives.BLSSignature,
};

pub const PendingAttestation = struct {
    aggregation_bits: []bool,
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
    attestation_1: ?*IndexedAttestation, // # [Modified in Electra:EIP7549]
    attestation_2: ?*IndexedAttestation, // # [Modified in Electra:EIP7549]
};

pub const Attestation = union(primitives.ForkType) {
    phase0: phase0.Attestation,
    altair: phase0.Attestation,
    bellatrix: phase0.Attestation,
    capella: phase0.Attestation,
    deneb: phase0.Attestation,
    electra: electra.Attestation,
};

pub const Deposit = struct {
    proof: [constants.DEPOSIT_CONTRACT_TREE_DEPTH + 1]primitives.Bytes32,
    data: ?*DepositData,
};

pub const VoluntaryExit = struct {
    epoch: primitives.Epoch,
    validator_index: primitives.ValidatorIndex,
};

pub const SignedVoluntaryExit = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.SignedVoluntaryExit,
    bellatrix: altair.SignedVoluntaryExit,
    capella: altair.SignedVoluntaryExit,
    deneb: altair.SignedVoluntaryExit,
    electra: altair.SignedVoluntaryExit,
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

pub const SyncAggregate = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.SyncAggregate,
    bellatrix: altair.SyncAggregate,
    capella: altair.SyncAggregate,
    deneb: altair.SyncAggregate,
    electra: altair.SyncAggregate,
};

pub const SyncCommittee = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.SyncCommittee,
    bellatrix: altair.SyncCommittee,
    capella: altair.SyncCommittee,
    deneb: altair.SyncCommittee,
    electra: altair.SyncCommittee,
};

pub const SyncCommitteeMessage = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.SyncCommitteeMessage,
    bellatrix: altair.SyncCommitteeMessage,
    capella: altair.SyncCommitteeMessage,
    deneb: altair.SyncCommitteeMessage,
    electra: altair.SyncCommitteeMessage,
};

pub const SyncCommitteeContribution = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.SyncCommitteeContribution,
    bellatrix: altair.SyncCommitteeContribution,
    capella: altair.SyncCommitteeContribution,
    deneb: altair.SyncCommitteeContribution,
    electra: altair.SyncCommitteeContribution,
};

pub const ContributionAndProof = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.ContributionAndProof,
    bellatrix: altair.ContributionAndProof,
    capella: altair.ContributionAndProof,
    deneb: altair.ContributionAndProof,
    electra: altair.ContributionAndProof,
};

pub const SignedContributionAndProof = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.SignedContributionAndProof,
    bellatrix: altair.SignedContributionAndProof,
    capella: altair.SignedContributionAndProof,
    deneb: altair.SignedContributionAndProof,
    electra: altair.SignedContributionAndProof,
};

pub const BeaconBlock = struct {
    slot: primitives.Slot,
    proposer_index: primitives.ValidatorIndex,
    parent_root: primitives.Root,
    state_root: primitives.Root,
    body: *BeaconBlockBody,
};

pub const BeaconBlockBody = union(primitives.ForkType) {
    phase0: phase0.BeaconBlockBody,
    altair: altair.BeaconBlockBody,
    bellatrix: bellatrix.BeaconBlockBody,
    capella: capella.BeaconBlockBody,
    deneb: deneb.BeaconBlockBody,
    electra: deneb.BeaconBlockBody,
};

pub const SignedBeaconBlock = struct {
    message: ?*BeaconBlock,
    signature: primitives.BLSSignature,
};

pub const SyncAggregatorSelectionData = struct {
    slot: primitives.Slot,
    subcommittee_index: u64,
};

pub const ExecutionPayloadHeader = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: bellatrix.ExecutionPayloadHeader,
    capella: capella.ExecutionPayloadHeader,
    deneb: deneb.ExecutionPayloadHeader,
    electra: electra.ExecutionPayloadHeader,
};

pub const ExecutionPayload = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: bellatrix.ExecutionPayload,
    capella: capella.ExecutionPayload,
    deneb: deneb.ExecutionPayload,
    electra: electra.ExecutionPayload,
};

pub const LightClientHeader = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.LightClientHeader,
    bellatrix: altair.LightClientHeader,
    capella: capella.LightClientHeader,
    deneb: capella.LightClientHeader,
    electra: capella.LightClientHeader,
};

pub const LightClientOptimisticUpdate = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.LightClientOptimisticUpdate,
    bellatrix: altair.LightClientOptimisticUpdate,
    capella: altair.LightClientOptimisticUpdate,
    deneb: altair.LightClientOptimisticUpdate,
    electra: altair.LightClientOptimisticUpdate,
};

pub const LightClientFinalityUpdate = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.LightClientFinalityUpdate,
    bellatrix: altair.LightClientFinalityUpdate,
    capella: altair.LightClientFinalityUpdate,
    deneb: altair.LightClientFinalityUpdate,
    electra: altair.LightClientFinalityUpdate,
};

pub const LightClientUpdate = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.LightClientUpdate,
    bellatrix: altair.LightClientUpdate,
    capella: altair.LightClientUpdate,
    deneb: altair.LightClientUpdate,
    electra: altair.LightClientUpdate,
};

pub const LightClientBootstrap = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: altair.LightClientBootstrap,
    bellatrix: altair.LightClientBootstrap,
    capella: altair.LightClientBootstrap,
    deneb: altair.LightClientBootstrap,
    electra: altair.LightClientBootstrap,
};

pub const PowBlock = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: bellatrix.PowBlock,
    capella: bellatrix.PowBlock,
    deneb: bellatrix.PowBlock,
    electra: bellatrix.PowBlock,
};

pub const Withdrawal = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: capella.Withdrawal,
    deneb: capella.Withdrawal,
    electra: capella.Withdrawal,
};

pub const BLSToExecutionChange = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: capella.BLSToExecutionChange,
    deneb: capella.BLSToExecutionChange,
    electra: capella.BLSToExecutionChange,
};

pub const SignedBLSToExecutionChange = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: capella.SignedBLSToExecutionChange,
    deneb: capella.SignedBLSToExecutionChange,
    electra: capella.SignedBLSToExecutionChange,
};

pub const HistoricalSummary = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: capella.HistoricalSummary,
    deneb: capella.HistoricalSummary,
    electra: capella.HistoricalSummary,
};

pub const BlobSidecar = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: deneb.BlobSidecar,
    electra: deneb.BlobSidecar,
};

pub const BlobIdentifier = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: deneb.BlobIdentifier,
    electra: deneb.BlobIdentifier,
};

pub const DepositRequest = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: NonExistType,
    electra: electra.DepositRequest,
};

pub const PendingBalanceDeposit = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: NonExistType,
    electra: electra.PendingBalanceDeposit,
};

pub const PendingPartialWithdrawal = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: NonExistType,
    electra: electra.PendingPartialWithdrawal,
};

pub const WithdrawalRequest = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: NonExistType,
    electra: electra.WithdrawalRequest,
};

pub const ConsolidationRequest = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: NonExistType,
    electra: electra.ConsolidationRequest,
};

pub const PendingConsolidation = union(primitives.ForkType) {
    phase0: NonExistType,
    altair: NonExistType,
    bellatrix: NonExistType,
    capella: NonExistType,
    deneb: NonExistType,
    electra: electra.PendingConsolidation,
};

pub const BeaconState = union(primitives.ForkType) {
    phase0: phase0.BeaconState,
    altair: altair.BeaconState,
    bellatrix: bellatrix.BeaconState,
    capella: capella.BeaconState,
    deneb: capella.BeaconState,
    electra: electra.BeaconState,

    /// slot returns the slot of the given state.
    /// @return The slot of the state.
    pub fn slot(self: *const BeaconState) primitives.Slot {
        return switch (self.*) {
            inline else => |state| state.beacon_state_ssz.slot,
        };
    }

    /// validators returns the validators of the given state.
    /// @return The validators of the state.
    pub fn validators(self: *const BeaconState) []const Validator {
        return switch (self.*) {
            inline else => |state| state.beacon_state_ssz.validators,
        };
    }

    pub fn finalizedCheckpointEpoch(self: *const BeaconState) primitives.Epoch {
        return switch (self.*) {
            inline else => |state| getCheckpointEpoch(state.beacon_state_ssz.finalized_checkpoint),
        };
    }

    /// getActiveValidatorIndices returns the indices of active validators for the given epoch.
    /// @param epoch The epoch for which to get the active validator indices.
    /// @return The indices of active validators for the given epoch.
    /// Spec pseudocode definition:
    /// def get_active_validator_indices(state: BeaconState, epoch: Epoch) -> Sequence[ValidatorIndex]:
    ///     """
    ///     Return the sequence of active validator indices at ``epoch``.
    ///     """
    ///     return [ValidatorIndex(i) for i, v in enumerate(state.validators) if is_active_validator(v, epoch)]
    pub fn getActiveValidatorIndices(self: *const BeaconState, epoch: primitives.Epoch) ![]const primitives.ValidatorIndex {
        var active_validators = std.ArrayList(primitives.ValidatorIndex).init(self.allocator());
        errdefer active_validators.deinit();

        for (self.validators(), 0..) |v, i| {
            if (v.isActiveValidator(epoch)) {
                try active_validators.append(@as(primitives.Epoch, i));
            }
        }

        return active_validators.toOwnedSlice();
    }

    /// getCurrentEpoch returns the current epoch for the given state.
    /// @return The current epoch.
    /// Spec pseudocode definition:
    /// def get_current_epoch(state: BeaconState) -> Epoch:
    /// """
    /// Return the current epoch.
    /// """
    /// return compute_epoch_at_slot(state.slot)
    pub fn getCurrentEpoch(self: *const BeaconState) primitives.Epoch {
        return primitives.computeEpochAtSlot(self.slot());
    }

    /// getValidatorChurnLimit returns the validator churn limit for the given state.
    /// The churn limit is the maximum number of validators who can leave the validator set in one epoch.
    /// @return The validator churn limit.
    /// Spec pseudocode definition:
    /// def get_validator_churn_limit(state: BeaconState) -> uint64:
    /// """
    /// Return the validator churn limit for the current epoch.
    /// """
    /// active_validator_indices = get_active_validator_indices(state, get_current_epoch(state))
    /// return max(config.MIN_PER_EPOCH_CHURN_LIMIT, uint64(len(active_validator_indices)) // config.CHURN_LIMIT_QUOTIENT)
    pub fn getValidatorChurnLimit(self: *const BeaconState) !u64 {
        const active_validator_indices = try self.getActiveValidatorIndices(self.getCurrentEpoch());
        defer self.allocator().free(active_validator_indices);
        const conf = configs.ActiveConfig.get();
        return @max(conf.MIN_PER_EPOCH_CHURN_LIMIT, @divFloor(@as(u64, active_validator_indices.len), conf.CHURN_LIMIT_QUOTIENT));
    }

    pub fn allocator(self: *const BeaconState) std.mem.Allocator {
        return switch (self.*) {
            inline else => |state| state.allocator,
        };
    }

    pub fn deinit(self: *BeaconState) void {
        switch (self.*) {
            inline else => |*state| state.deinit(),
        }
    }
};

pub fn getCheckpointEpoch(checkpoint: ?*Checkpoint) primitives.Epoch {
    return if (checkpoint) |c| c.epoch else @as(primitives.Epoch, 0);
}

/// isSlashableAttestationData checks if two attestations are slashable according to Casper FFG rules.
/// @param data_1 The first attestation data.
/// @param data_2 The second attestation data.
/// @return True if the attestations are slashable, false otherwise.
/// Spec pseudocode definition:
/// def is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
///    """
///    Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
///    """
///    return (
///          # Double vote
///        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
///         # Surround vote
///        (data_1.source.epoch < data_2.source.epoch and data_2.target.epoch < data_1.target.epoch)
///     )
pub fn isSlashableAttestationData(data1: AttestationData, data2: AttestationData) bool {
    // Check if `data_1` and `data_2` are slashable according to Casper FFG rules.
    return (
    // Double vote
        (!std.meta.eql(data1, data2) and data1.target.epoch == data2.target.epoch) or
        // Surround vote
        (data1.source.epoch < data2.source.epoch and data2.target.epoch < data1.target.epoch));
}

// pub fn compute_fork_data_root(current_version: primitives.Version, genesis_validators_root: primitives.Root) primitives.Root {
//     const fork_data = ForkData{
//         .current_version = current_version,
//         .genesis_validators_root = genesis_validators_root,
//     };
//
//    return ssz.serialize_root(&fork_data);
// }

test "test isSlashableAttestationData" {
    const data1 = AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
    };

    const data2 = AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
    };

    try std.testing.expectEqual(isSlashableAttestationData(data1, data2), false);

    const data3 = AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
    };

    const data4 = AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
        .target = Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
    };

    try std.testing.expectEqual(isSlashableAttestationData(data3, data4), true);
    try std.testing.expectEqual(isSlashableAttestationData(data1, data4), false);
}

test "test Attestation" {
    const attestation = Attestation{
        .phase0 = phase0.Attestation{
            .aggregation_bits = &[_]bool{},
            .data = undefined,
            .signature = undefined,
        },
    };

    try std.testing.expectEqual(attestation.phase0.aggregation_bits.len, 0);

    const attestation1 = Attestation{
        .altair = phase0.Attestation{
            .aggregation_bits = &[_]bool{},
            .data = undefined,
            .signature = undefined,
        },
    };

    try std.testing.expectEqual(attestation1.altair.aggregation_bits.len, 0);
}

test "test SignedVoluntaryExit" {
    const exit = SignedVoluntaryExit{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(exit.phase0, NonExistType{});

    const exit1 = SignedVoluntaryExit{
        .altair = altair.SignedVoluntaryExit{
            .message = undefined,
            .signature = undefined,
        },
    };

    try std.testing.expectEqual(exit1.altair.message, undefined);
}

test "test SyncAggregate" {
    const aggregate = SyncAggregate{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(aggregate.phase0, NonExistType{});

    const aggregate1 = SyncAggregate{
        .altair = altair.SyncAggregate{
            .sync_committee_bits = &[_]bool{},
            .sync_committee_signature = undefined,
        },
    };

    try std.testing.expectEqual(aggregate1.altair.sync_committee_bits.len, 0);
}

test "test BeaconBlock" {
    const block = BeaconBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = undefined,
        .state_root = undefined,
        .body = undefined,
    };

    try std.testing.expectEqual(block.slot, 0);
}

test "test BeaconBlockBody" {
    const body = BeaconBlockBody{
        .phase0 = phase0.BeaconBlockBody{
            .randao_reveal = undefined,
            .eth1_data = undefined,
            .graffiti = undefined,
            .proposer_slashings = undefined,
            .attester_slashings = undefined,
            .attestations = undefined,
            .deposits = undefined,
            .voluntary_exits = undefined,
        },
    };

    try std.testing.expectEqual(body.phase0.randao_reveal.len, 96);

    const body1 = BeaconBlockBody{
        .altair = altair.BeaconBlockBody{
            .randao_reveal = undefined,
            .eth1_data = undefined,
            .graffiti = undefined,
            .proposer_slashings = undefined,
            .attester_slashings = undefined,
            .attestations = undefined,
            .deposits = undefined,
            .voluntary_exits = undefined,
            .sync_aggregate = undefined,
        },
    };

    try std.testing.expectEqual(body1.altair.randao_reveal.len, 96);
}

test "test SignedBeaconBlockHeader" {
    const header = SignedBeaconBlockHeader{
        .message = undefined,
        .signature = undefined,
    };

    try std.testing.expectEqual(header.message, undefined);
}

test "test LightClientHeader" {
    const header = LightClientHeader{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(header.phase0, NonExistType{});

    const header1 = LightClientHeader{
        .altair = altair.LightClientHeader{
            .beacon = null,
        },
    };

    try std.testing.expectEqual(header1.altair.beacon, null);
}

test "test LightClientOptimisticUpdate" {
    const update = LightClientOptimisticUpdate{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(update.phase0, NonExistType{});

    const update1 = LightClientOptimisticUpdate{
        .altair = altair.LightClientOptimisticUpdate{
            .attested_header = null,
            .sync_aggregate = null,
            .signature_slot = 0,
        },
    };

    try std.testing.expectEqual(update1.altair.attested_header, null);
}

test "test LightClientFinalityUpdate" {
    const update = LightClientFinalityUpdate{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(update.phase0, NonExistType{});

    const finality_branch = primitives.FinalityBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 6,
    };

    const update1 = LightClientFinalityUpdate{
        .altair = altair.LightClientFinalityUpdate{
            .attested_header = null,
            .finalized_header = null,
            .finality_branch = finality_branch,
            .sync_aggregate = null,
            .signature_slot = 0,
        },
    };

    try std.testing.expectEqual(update1.altair.signature_slot, 0);
}

test "test LightClientUpdate" {
    const update = LightClientUpdate{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(update.phase0, NonExistType{});

    const next_sync_committee_branch = primitives.NextSyncCommitteeBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 5,
    };

    const finality_branch = primitives.FinalityBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 6,
    };

    const update1 = LightClientUpdate{
        .altair = altair.LightClientUpdate{
            .attested_header = null,
            .next_sync_committee = null,
            .next_sync_committee_branch = next_sync_committee_branch,
            .finalized_header = null,
            .finality_branch = finality_branch,
            .sync_aggregate = null,
            .signature_slot = 0,
        },
    };

    try std.testing.expectEqual(update1.altair.finality_branch.altair.len, 6);
}

test "test LightClientBootstrap" {
    const bootstrap = LightClientBootstrap{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(bootstrap.phase0, NonExistType{});

    const current_sync_committee_branch = primitives.CurrentSyncCommitteeBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 5,
    };

    const bootstrap1 = LightClientBootstrap{
        .altair = altair.LightClientBootstrap{
            .header = null,
            .current_sync_committee = null,
            .current_sync_committee_branch = current_sync_committee_branch,
        },
    };

    try std.testing.expectEqual(bootstrap1.altair.current_sync_committee_branch.altair.len, 5);
}

test "test PowBlock" {
    const block = PowBlock{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(block.phase0, NonExistType{});

    const block1 = PowBlock{
        .bellatrix = bellatrix.PowBlock{
            .block_hash = undefined,
            .parent_hash = undefined,
            .total_difficulty = 0,
        },
    };

    try std.testing.expectEqual(block1.bellatrix.total_difficulty, 0);
}

test "test Withdrawal" {
    const withdrawal = Withdrawal{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(withdrawal.phase0, NonExistType{});

    const withdrawal1 = Withdrawal{
        .capella = capella.Withdrawal{
            .index = 0,
            .validator_index = 0,
            .address = undefined,
            .amount = 0,
        },
    };

    try std.testing.expectEqual(withdrawal1.capella.index, 0);
}

test "test BLSToExecutionChange" {
    const change = BLSToExecutionChange{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(change.phase0, NonExistType{});

    const change1 = BLSToExecutionChange{
        .capella = capella.BLSToExecutionChange{
            .validator_index = 0,
            .from_bls_pubkey = undefined,
            .to_execution_address = undefined,
        },
    };

    try std.testing.expectEqual(change1.capella.validator_index, 0);
}

test "test SignedBLSToExecutionChange" {
    const change = SignedBLSToExecutionChange{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(change.phase0, NonExistType{});

    const change1 = SignedBLSToExecutionChange{
        .capella = capella.SignedBLSToExecutionChange{
            .message = null,
            .signature = undefined,
        },
    };

    try std.testing.expectEqual(change1.capella.message, null);
}

test "test HistoricalSummary" {
    const summary = HistoricalSummary{
        .capella = capella.HistoricalSummary{
            .block_summary_root = undefined,
            .state_summary_root = undefined,
        },
    };

    try std.testing.expectEqual(summary.capella.block_summary_root.len, 32);
}

test "test ExecutionPayload" {
    const payload = ExecutionPayload{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(payload.phase0, NonExistType{});

    const payload1 = ExecutionPayload{
        .capella = capella.ExecutionPayload{
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
        },
    };

    try std.testing.expectEqual(payload1.capella.block_number, 21);
}

test "test BlobSidecar" {
    const sidecar = BlobSidecar{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(sidecar.phase0, NonExistType{});

    const sidecar1 = BlobSidecar{
        .deneb = deneb.BlobSidecar{
            .index = 3,
            .blob = undefined,
            .kzg_commitment = undefined,
            .kzg_proof = undefined,
            .signed_block_header = undefined,
            .kzg_commitment_inclusion_proof = undefined,
        },
    };

    try std.testing.expectEqual(sidecar1.deneb.index, 3);
}

test "test BlobIdentifier" {
    const identifier = BlobIdentifier{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(identifier.phase0, NonExistType{});

    const identifier1 = BlobIdentifier{
        .deneb = deneb.BlobIdentifier{
            .block_root = undefined,
            .index = undefined,
        },
    };

    try std.testing.expectEqual(identifier1.deneb.block_root.len, 32);
}

test "test PendingConsolidation" {
    const consolidation = PendingConsolidation{
        .phase0 = NonExistType{},
    };

    try std.testing.expectEqual(consolidation.phase0, NonExistType{});

    const consolidation1 = PendingConsolidation{
        .electra = electra.PendingConsolidation{
            .source_index = 0,
            .target_index = 0,
        },
    };

    try std.testing.expectEqual(consolidation1.electra.source_index, 0);
}

test "test BeaconState" {
    const state_ssz = phase0.BeaconStateSSZ{
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
    };

    const state = BeaconState{
        .phase0 = phase0.BeaconState{
            .allocator = std.testing.allocator,
            .beacon_state_ssz = state_ssz,
        },
    };

    try std.testing.expectEqual(state.phase0.beacon_state_ssz.genesis_time, 0);
}

test "test Validator" {
    const validator = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };

    try std.testing.expectEqual(validator.effective_balance, 0);
}

test "test isActiveValidator" {
    const validator = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 0,
    };
    const epoch: primitives.Epoch = 5;
    const result = validator.isActiveValidator(epoch);
    try std.testing.expectEqual(result, true);
}

test "test isEligibleForActivationQueue" {
    preset.ActivePreset.set(preset.Presets.mainnet);
    defer preset.ActivePreset.reset();
    const validator = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = preset.ActivePreset.get().MIN_ACTIVATION_BALANCE,
        .slashed = false,
        .activation_eligibility_epoch = constants.FAR_FUTURE_EPOCH,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    const result = validator.isEligibleForActivationQueue();
    try std.testing.expectEqual(result, true);
}

test "test isEligibleForActivation" {
    var finalized_checkpoint = Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    const state_ssz = phase0.BeaconStateSSZ{
        .genesis_time = 0,
        .genesis_validators_root = undefined,
        .slot = 0,
        .fork = undefined,
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
        .finalized_checkpoint = &finalized_checkpoint,
        .latest_block_header = undefined,
    };

    const state = BeaconState{
        .phase0 = phase0.BeaconState{
            .allocator = std.testing.allocator,
            .beacon_state_ssz = state_ssz,
        },
    };

    const validator = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = constants.FAR_FUTURE_EPOCH,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };

    const result = validator.isEligibleForActivation(&state);
    try std.testing.expectEqual(result, true);

    const validator2 = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 10,
        .activation_epoch = constants.FAR_FUTURE_EPOCH,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };

    const result2 = validator2.isEligibleForActivation(&state);
    try std.testing.expectEqual(result2, false);
}

test "test isSlashableValidator" {
    preset.ActivePreset.set(preset.Presets.mainnet);
    defer preset.ActivePreset.reset();
    const validator = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };
    const epoch: primitives.Epoch = 5;
    const result = validator.isSlashableValidator(epoch);
    try std.testing.expectEqual(result, true);

    const validator2 = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 5,
    };
    const epoch2: primitives.Epoch = 5;
    const result2 = validator2.isSlashableValidator(epoch2);
    try std.testing.expectEqual(result2, false);
}

test "test_getActiveValidatorIndices_withTwoActiveValidators" {
    var finalized_checkpoint = Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    var validators = std.ArrayList(Validator).init(std.testing.allocator);
    defer validators.deinit();

    const validator1 = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const validator2 = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };
    try validators.append(validator1);
    try validators.append(validator2);

    const state_ssz = altair.BeaconStateSSZ{
        .genesis_time = 0,
        .genesis_validators_root = .{0} ** 32,
        .slot = 0,
        .fork = undefined,
        .block_roots = undefined,
        .state_roots = undefined,
        .historical_roots = undefined,
        .eth1_data = undefined,
        .eth1_data_votes = undefined,
        .eth1_deposit_index = 0,
        .validators = validators.items,
        .balances = undefined,
        .randao_mixes = undefined,
        .slashings = undefined,
        .previous_epoch_attestations = undefined,
        .current_epoch_attestations = undefined,
        .justification_bits = undefined,
        .previous_justified_checkpoint = undefined,
        .current_justified_checkpoint = undefined,
        .finalized_checkpoint = &finalized_checkpoint,
        .latest_block_header = undefined,
        .inactivity_scores = undefined,
        .current_sync_committee = undefined,
        .next_sync_committee = undefined,
    };

    const state = BeaconState{
        .altair = altair.BeaconState{
            .allocator = std.testing.allocator,
            .beacon_state_ssz = state_ssz,
        },
    };

    const indices = try state.getActiveValidatorIndices(@as(primitives.Epoch, 5));
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqual(indices.len, 2);
}

test "test getValidatorChurnLimit" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    configs.ActiveConfig.set(preset.Presets.minimal);
    defer configs.ActiveConfig.reset();
    var finalized_checkpoint = Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };

    var validators = std.ArrayList(Validator).init(std.testing.allocator);
    defer validators.deinit();

    const validator1 = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };

    const validator2 = Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };

    // add 800 validators
    for (0..400) |_| {
        try validators.append(validator1);
        try validators.append(validator2);
    }

    const state_ssz = altair.BeaconStateSSZ{
        .genesis_time = 0,
        .genesis_validators_root = .{0} ** 32,
        .slot = 0,
        .fork = undefined,
        .block_roots = undefined,
        .state_roots = undefined,
        .historical_roots = undefined,
        .eth1_data = undefined,
        .eth1_data_votes = undefined,
        .eth1_deposit_index = 0,
        .validators = validators.items,
        .balances = undefined,
        .randao_mixes = undefined,
        .slashings = undefined,
        .previous_epoch_attestations = undefined,
        .current_epoch_attestations = undefined,
        .justification_bits = undefined,
        .previous_justified_checkpoint = undefined,
        .current_justified_checkpoint = undefined,
        .finalized_checkpoint = &finalized_checkpoint,
        .latest_block_header = undefined,
        .inactivity_scores = undefined,
        .current_sync_committee = undefined,
        .next_sync_committee = undefined,
    };

    const state = BeaconState{
        .altair = altair.BeaconState{
            .allocator = std.testing.allocator,
            .beacon_state_ssz = state_ssz,
        },
    };

    const churn_limit = try state.getValidatorChurnLimit();
    try std.testing.expectEqual(churn_limit, 25);

    var validators1 = std.ArrayList(Validator).init(std.testing.allocator);
    defer validators1.deinit();

    try validators1.append(validator1);
    try validators1.append(validator2);

    const state_ssz1 = altair.BeaconStateSSZ{
        .genesis_time = 0,
        .genesis_validators_root = .{0} ** 32,
        .slot = 0,
        .fork = undefined,
        .block_roots = undefined,
        .state_roots = undefined,
        .historical_roots = undefined,
        .eth1_data = undefined,
        .eth1_data_votes = undefined,
        .eth1_deposit_index = 0,
        .validators = validators1.items,
        .balances = undefined,
        .randao_mixes = undefined,
        .slashings = undefined,
        .previous_epoch_attestations = undefined,
        .current_epoch_attestations = undefined,
        .justification_bits = undefined,
        .previous_justified_checkpoint = undefined,
        .current_justified_checkpoint = undefined,
        .finalized_checkpoint = &finalized_checkpoint,
        .latest_block_header = undefined,
        .inactivity_scores = undefined,
        .current_sync_committee = undefined,
        .next_sync_committee = undefined,
    };

    const state1 = BeaconState{
        .altair = altair.BeaconState{
            .allocator = std.testing.allocator,
            .beacon_state_ssz = state_ssz1,
        },
    };

    const churn_limit1 = try state1.getValidatorChurnLimit();
    try std.testing.expectEqual(churn_limit1, 2);
}
