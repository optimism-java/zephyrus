const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const committee_helper = @import("../../consensus/helpers/committee.zig");
const electra = @import("../../consensus/electra/types.zig");

/// getIndexedAttestation returns the indexed attestation corresponding to the attestation.
/// @param state The state.
/// @param attestation The attestation.
/// @param allocator The allocator to use.
/// @returns The indexed attestation.
/// Spec pseudocode definition:
/// def get_indexed_attestation(state: BeaconState, attestation: Attestation) -> IndexedAttestation:
///     """
///     Return the indexed attestation corresponding to ``attestation``.
///    """
///     attesting_indices = get_attesting_indices(state, attestation)
///
///     return IndexedAttestation(
///       attesting_indices=sorted(attesting_indices),
///       data=attestation.data,
///       signature=attestation.signature,
///     )
pub fn getIndexedAttestation(state: *const consensus.BeaconState, attestation: *const consensus.Attestation, allocator: std.mem.Allocator) !consensus.IndexedAttestation {
    // Return the indexed attestation corresponding to `attestation`.
    var attesting_indices = try getAttestingIndices(state, attestation, allocator);
    defer attesting_indices.deinit();

    var keys = try std.ArrayList(primitives.ValidatorIndex).initCapacity(allocator, attesting_indices.count());
    defer keys.deinit();

    var indexIterator = attesting_indices.keyIterator();
    while (indexIterator.next()) |key| {
        try keys.append(key.*);
    }

    std.mem.sort(primitives.ValidatorIndex, keys.items, {}, comptime std.sort.asc(primitives.ValidatorIndex));

    return consensus.IndexedAttestation{
        .attesting_indices = try keys.toOwnedSlice(),
        .data = attestation.data(),
        .signature = attestation.signature(),
    };
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
pub fn isSlashableAttestationData(data1: consensus.AttestationData, data2: consensus.AttestationData) bool {
    // Check if `data_1` and `data_2` are slashable according to Casper FFG rules.
    return (
    // Double vote
        (!std.meta.eql(data1, data2) and data1.target.epoch == data2.target.epoch) or
        // Surround vote
        (data1.source.epoch < data2.source.epoch and data2.target.epoch < data1.target.epoch));
}

/// getCommitteeIndices returns the indices of the committee for the given `committeeBits`.
/// @param committeeBits The committee bits.
/// @param allocator The allocator to use.
/// @return The indices of the committee.
/// Spec pseudocode definition:
/// def get_committee_indices(committee_bits: Bitvector) -> Sequence[CommitteeIndex]:
///     return [CommitteeIndex(index) for index, bit in enumerate(committee_bits) if bit]
pub fn getCommitteeIndices(committeeBits: []const bool, allocator: std.mem.Allocator) ![]primitives.CommitteeIndex {
    var indices = try std.ArrayList(primitives.CommitteeIndex).initCapacity(allocator, committeeBits.len);
    defer indices.deinit();

    for (committeeBits, 0..) |bit, index| {
        if (bit) {
            try indices.append(@as(primitives.CommitteeIndex, index));
        }
    }

    return indices.toOwnedSlice();
}

/// getAttestingIndices returns the indices of the validators that are attesting to the given attestation.
/// @param state The state.
/// @param attestation The attestation.
/// @param allocator The allocator to use.
/// @return The indices of the validators that are attesting to the given attestation.
/// Spec pseudocode definition:
/// def get_attesting_indices(state: BeaconState, attestation: Attestation) -> Set[ValidatorIndex]:
///     """
///     Return the set of attesting indices corresponding to ``aggregation_bits`` and ``committee_bits``.
///    """
///    output: Set[ValidatorIndex] = set()
///    committee_indices = get_committee_indices(attestation.committee_bits)
///    committee_offset = 0
///    for index in committee_indices:
///        committee = get_beacon_committee(state, attestation.data.slot, index)
///        committee_attesters = set(
///            index for i, index in enumerate(committee) if attestation.aggregation_bits[committee_offset + i])
///        output = output.union(committee_attesters)
///
///        committee_offset += len(committee)
///   return output
/// Before electra:
/// def get_attesting_indices(state: BeaconState, attestation: Attestation) -> Set[ValidatorIndex]:
///    """
///    Return the set of attesting indices corresponding to ``data`` and ``bits``.
///   """
///   committee = get_beacon_committee(state, attestation.data.slot, attestation.data.index)
///   return set(index for i, index in enumerate(committee) if attestation.aggregation_bits[i])
pub fn getAttestingIndices(state: *const consensus.BeaconState, attestation: *const consensus.Attestation, allocator: std.mem.Allocator) !std.AutoHashMap(primitives.ValidatorIndex, void) {
    var output = std.AutoHashMap(primitives.ValidatorIndex, void).init(allocator);
    errdefer output.deinit();

    switch (state.*) {
        .electra => {
            const committee_indices = try getCommitteeIndices(attestation.electra.committee_bits, allocator);
            defer allocator.free(committee_indices);

            var committeeOffset: usize = 0;

            for (committee_indices) |committee_index| {
                const committee = try committee_helper.getBeaconCommittee(state, attestation.data().slot, committee_index, allocator);
                defer allocator.free(committee);
                try processElectraCommittee(committee, attestation, committeeOffset, &output);
                committeeOffset += committee.len;
            }
        },
        else => {
            const committee = try committee_helper.getBeaconCommittee(state, attestation.data().slot, attestation.data().index, allocator);
            defer allocator.free(committee);
            try processRegularCommittee(committee, attestation, &output);
        },
    }
    return output;
}

fn processElectraCommittee(
    committee: []const primitives.ValidatorIndex,
    attestation: *const consensus.Attestation,
    committee_offset: usize,
    output: *std.AutoHashMap(primitives.ValidatorIndex, void),
) !void {
    for (committee, 0..) |validator_index, i| {
        if (attestation.aggregationBits()[committee_offset + i]) {
            try output.put(validator_index, {});
        }
    }
}

fn processRegularCommittee(
    committee: []const primitives.ValidatorIndex,
    attestation: *const consensus.Attestation,
    output: *std.AutoHashMap(primitives.ValidatorIndex, void),
) !void {
    for (committee, 0..) |validator_index, i| {
        if (attestation.aggregationBits()[i]) {
            try output.put(validator_index, {});
        }
    }
}

test "test isSlashableAttestationData" {
    const data1 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
    };

    const data2 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
    };

    try std.testing.expectEqual(isSlashableAttestationData(data1, data2), false);

    const data3 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 0,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
    };

    const data4 = consensus.AttestationData{
        .slot = 0,
        .index = 0,
        .beacon_block_root = undefined,
        .source = consensus.Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
        .target = consensus.Checkpoint{
            .epoch = 1,
            .root = undefined,
        },
    };

    try std.testing.expectEqual(isSlashableAttestationData(data3, data4), true);
    try std.testing.expectEqual(isSlashableAttestationData(data1, data4), false);
}

test "test getCommitteeIndices" {
    const committeeBits = [_]bool{ true, false, true, false, true, false, true, false };
    const allocator = std.testing.allocator;
    const indices = try getCommitteeIndices(&committeeBits, allocator);
    defer allocator.free(indices);
    try std.testing.expectEqual(4, indices.len);
    try std.testing.expectEqual(0, indices[0]);
    try std.testing.expectEqual(2, indices[1]);
    try std.testing.expectEqual(4, indices[2]);
    try std.testing.expectEqual(6, indices[3]);
}

test "test getAttestingIndices" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };
    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();
    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };
    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };
    for (0..1000) |_| {
        try validators.append(validator1);
        try validators.append(validator2);
    }

    var block_roots = std.ArrayList(primitives.Root).init(std.testing.allocator);
    defer block_roots.deinit();
    const block_root1 = .{0} ** 32;
    const block_root2 = .{1} ** 32;
    const block_root3 = .{2} ** 32;
    try block_roots.append(block_root1);
    try block_roots.append(block_root2);
    try block_roots.append(block_root3);

    var randao_mixes = try std.ArrayList(primitives.Bytes32).initCapacity(std.testing.allocator, preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR);
    defer randao_mixes.deinit();
    for (0..preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR) |slot_index| {
        try randao_mixes.append(.{@as(u8, @intCast(slot_index))} ** 32);
    }

    var aggregation_bits = [_]bool{ true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true };
    var committee_bits = [_]bool{ true, false, true, false };
    const attestation = consensus.Attestation{
        .electra = electra.Attestation{
            .data = consensus.AttestationData{
                .slot = 100,
                .index = 1,
                .beacon_block_root = .{0} ** 32,
                .source = consensus.Checkpoint{
                    .epoch = 0,
                    .root = .{0} ** 32,
                },
                .target = consensus.Checkpoint{
                    .epoch = 0,
                    .root = .{0} ** 32,
                },
            },
            .aggregation_bits = &aggregation_bits,
            .signature = undefined,
            .committee_bits = &committee_bits,
        },
    };

    const state = consensus.BeaconState{
        .electra = electra.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 100,
            .fork = undefined,
            .block_roots = block_roots.items,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = validators.items,
            .balances = &[_]u64{},
            .randao_mixes = randao_mixes.items,
            .slashings = &[_]u64{},
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = &[_]u64{},
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .latest_execution_payload_header = undefined,
            .historical_summaries = undefined,
            .pending_balance_deposits = undefined,
            .pending_partial_withdrawals = undefined,
            .pending_consolidations = undefined,
            .deposit_requests_start_index = 0,
            .previous_epoch_participation = undefined,
            .current_epoch_participation = undefined,
        },
    };

    var indices = try getAttestingIndices(&state, &attestation, std.testing.allocator);
    defer indices.deinit();
    try std.testing.expect(indices.count() == 32);
}

test "test getIndexedAttestation" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };
    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();
    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 10,
        .withdrawable_epoch = 10,
    };
    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 20,
        .withdrawable_epoch = 20,
    };
    for (0..1000) |_| {
        try validators.append(validator1);
        try validators.append(validator2);
    }

    var block_roots = std.ArrayList(primitives.Root).init(std.testing.allocator);
    defer block_roots.deinit();
    const block_root1 = .{0} ** 32;
    const block_root2 = .{1} ** 32;
    const block_root3 = .{2} ** 32;
    try block_roots.append(block_root1);
    try block_roots.append(block_root2);
    try block_roots.append(block_root3);

    var randao_mixes = try std.ArrayList(primitives.Bytes32).initCapacity(std.testing.allocator, preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR);
    defer randao_mixes.deinit();
    for (0..preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR) |slot_index| {
        try randao_mixes.append(.{@as(u8, @intCast(slot_index))} ** 32);
    }

    var aggregation_bits = [_]bool{ true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true };
    var committee_bits = [_]bool{ true, false, true, false };
    const attestation = consensus.Attestation{
        .electra = electra.Attestation{
            .data = consensus.AttestationData{
                .slot = 100,
                .index = 1,
                .beacon_block_root = .{0} ** 32,
                .source = consensus.Checkpoint{
                    .epoch = 0,
                    .root = .{0} ** 32,
                },
                .target = consensus.Checkpoint{
                    .epoch = 0,
                    .root = .{0} ** 32,
                },
            },
            .aggregation_bits = &aggregation_bits,
            .signature = undefined,
            .committee_bits = &committee_bits,
        },
    };

    const state = consensus.BeaconState{
        .electra = electra.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{0} ** 32,
            .slot = 100,
            .fork = undefined,
            .block_roots = block_roots.items,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = validators.items,
            .balances = &[_]u64{},
            .randao_mixes = randao_mixes.items,
            .slashings = &[_]u64{},
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = &[_]u64{},
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .latest_execution_payload_header = undefined,
            .historical_summaries = undefined,
            .pending_balance_deposits = undefined,
            .pending_partial_withdrawals = undefined,
            .pending_consolidations = undefined,
            .deposit_requests_start_index = 0,
            .previous_epoch_participation = undefined,
            .current_epoch_participation = undefined,
        },
    };

    const indexed_attestation = try getIndexedAttestation(&state, &attestation, std.testing.allocator);
    defer indexed_attestation.deinit(std.testing.allocator);
    try std.testing.expectEqual(indexed_attestation.attesting_indices.len, 32);
}
