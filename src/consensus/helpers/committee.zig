const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");
const shuffle_helper = @import("../../consensus/helpers/shuffle.zig");
const seed_helper = @import("../../consensus/helpers/seed.zig");
const sha256 = std.crypto.hash.sha2.Sha256;

/// Calculates the committee count per slot for a given epoch
/// Returns: The number of committees per slot
/// Spec pseudocode definition:
/// def get_committee_count_per_slot(state: BeaconState, epoch: Epoch) -> uint64:
///     """
///     Return the number of committees in each slot for the given ``epoch``.
///     """
///     return max(uint64(1), min(
///         MAX_COMMITTEES_PER_SLOT,
///         uint64(len(get_active_validator_indices(state, epoch))) // SLOTS_PER_EPOCH // TARGET_COMMITTEE_SIZE,
///     ))
pub fn getCommitteeCountPerSlot(state: *const consensus.BeaconState, epoch: primitives.Epoch, allocator: std.mem.Allocator) !u64 {
    const active_validator_indices = try validator_helper.getActiveValidatorIndices(state, epoch, allocator);
    defer allocator.free(active_validator_indices);

    const active_validator_count = active_validator_indices.len;
    std.log.debug("active_validator_count: {}\n", .{active_validator_count});
    const slots_per_epoch = preset.ActivePreset.get().SLOTS_PER_EPOCH;
    const target_committee_size = preset.ActivePreset.get().TARGET_COMMITTEE_SIZE;

    const committees_per_slot = @divFloor(active_validator_count, slots_per_epoch * target_committee_size);

    return @max(@as(u64, 1), @min(preset.ActivePreset.get().MAX_COMMITTEES_PER_SLOT, committees_per_slot));
}

/// computeCommittee returns the committee for the current epoch.
/// @param indices - The validator indices.
/// @param seed - The seed.
/// @param index - The index of the committee.
/// @param count - The number of committees.
/// @param allocator - The allocator.
/// @returns The committee for the current epoch.
/// Spec pseudocode definition:
/// def compute_committee(indices: Sequence[ValidatorIndex],
///                       seed: Bytes32,
///                       index: uint64,
///                       count: uint64) -> Sequence[ValidatorIndex]:
///     """
///     Return the committee corresponding to ``indices``, ``seed``, ``index``, and committee ``count``.
///     """
///     start = (len(indices) * index) // count
///     end = (len(indices) * uint64(index + 1)) // count
///     return [indices[compute_shuffled_index(uint64(i), uint64(len(indices)), seed)] for i in range(start, end)]
/// Note: Caller is responsible for freeing the returned slice.
pub fn computeCommittee(indices: []const primitives.ValidatorIndex, seed: primitives.Bytes32, index: u64, count: u64, allocator: std.mem.Allocator) ![]primitives.ValidatorIndex {
    const len = indices.len;
    const start = @divFloor(len * index, count);
    const end = @divFloor(len * (index + 1), count);
    var result = std.ArrayList(primitives.ValidatorIndex).init(allocator);
    defer result.deinit();

    var i: u64 = start;
    while (i < end) : (i += 1) {
        const shuffled_index = try shuffle_helper.computeShuffledIndex(@as(u64, i), @as(u64, len), seed);
        try result.append(indices[shuffled_index]);
    }

    return result.toOwnedSlice();
}

/// getBeaconCommittee returns the beacon committee for the current epoch.
/// @param state - The beacon state.
/// @param slot - The slot.
/// @param index - The index of the committee.
/// @param allocator - The allocator.
/// @returns The beacon committee for the current epoch.
/// Spec pseudocode definition:
/// def get_beacon_committee(state: BeaconState, slot: Slot, index: CommitteeIndex) -> Sequence[ValidatorIndex]:
///     """
///     Return the beacon committee at ``slot`` for ``index``.
///     """
///     epoch = compute_epoch_at_slot(slot)
///     committees_per_slot = get_committee_count_per_slot(state, epoch)
///     return compute_committee(
///         indices=get_active_validator_indices(state, epoch),
///         seed=get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
///         index=(slot % SLOTS_PER_EPOCH) * committees_per_slot + index,
///         count=committees_per_slot * SLOTS_PER_EPOCH,
///     )
/// Note: Caller is responsible for freeing the returned slice.
pub fn getBeaconCommittee(state: *const consensus.BeaconState, slot: primitives.Slot, index: primitives.CommitteeIndex, allocator: std.mem.Allocator) ![]primitives.ValidatorIndex {
    const epoch = epoch_helper.computeEpochAtSlot(slot);
    const committeesPerSlot = try getCommitteeCountPerSlot(state, epoch, allocator);
    const indices = try validator_helper.getActiveValidatorIndices(state, epoch, allocator);
    defer allocator.free(indices);
    const seed = seed_helper.getSeed(state, epoch, constants.DOMAIN_BEACON_ATTESTER);
    const i = @mod(slot, preset.ActivePreset.get().SLOTS_PER_EPOCH) * committeesPerSlot + index;
    const count = committeesPerSlot * preset.ActivePreset.get().SLOTS_PER_EPOCH;
    return computeCommittee(indices, seed, i, count, allocator);
}

/// getBeaconProposerIndex returns the beacon proposer index for the current epoch.
/// @param state - The beacon state.
/// @param allocator - The allocator.
/// @returns The beacon proposer index for the current epoch.
/// Spec pseudocode definition:
/// def get_beacon_proposer_index(state: BeaconState) -> ValidatorIndex:
///     """
///     Return the beacon proposer index at the current slot.
///     """
///     epoch = get_current_epoch(state)
///     seed = hash(get_seed(state, epoch, DOMAIN_BEACON_PROPOSER) + uint_to_bytes(state.slot))
///     indices = get_active_validator_indices(state, epoch)
///     return compute_proposer_index(state, indices, seed)
pub fn getBeaconProposerIndex(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !primitives.ValidatorIndex {
    const epoch = epoch_helper.getCurrentEpoch(state);
    const seed_origin = seed_helper.getSeed(state, epoch, constants.DOMAIN_BEACON_PROPOSER) ++ std.mem.asBytes(&state.slot());
    std.log.debug("seed_origin: {any}\n", .{seed_origin});
    var seed: primitives.Bytes32 = undefined;
    sha256.hash(seed_origin, &seed, .{});
    const indices = try validator_helper.getActiveValidatorIndices(state, epoch, allocator);
    defer allocator.free(indices);
    return validator_helper.computeProposerIndex(state, indices, seed);
}

/// getNextSyncCommitteeIndices returns the next sync committee indices.
/// @param state - The beacon state.
/// @param allocator - The allocator.
/// @returns The next sync committee indices.
/// Spec pseudocode definition:
/// def get_next_sync_committee_indices(state: BeaconState) -> Sequence[ValidatorIndex]:
///     """
///     Return the sync committee indices, with possible duplicates, for the next sync committee.
///     """
///     epoch = Epoch(get_current_epoch(state) + 1)
///
///     MAX_RANDOM_BYTE = 2**8 - 1
///     active_validator_indices = get_active_validator_indices(state, epoch)
///     active_validator_count = uint64(len(active_validator_indices))
///     seed = get_seed(state, epoch, DOMAIN_SYNC_COMMITTEE)
///     i = 0
///     sync_committee_indices: List[ValidatorIndex] = []
///     while len(sync_committee_indices) < SYNC_COMMITTEE_SIZE:
///        shuffled_index = compute_shuffled_index(uint64(i % active_validator_count), active_validator_count, seed)
///        candidate_index = active_validator_indices[shuffled_index]
///        random_byte = hash(seed + uint_to_bytes(uint64(i // 32)))[i % 32]
///        effective_balance = state.validators[candidate_index].effective_balance
///        # [Modified in Electra:EIP7251]
///        if effective_balance * MAX_RANDOM_BYTE >= MAX_EFFECTIVE_BALANCE_ELECTRA * random_byte:
///            sync_committee_indices.append(candidate_index)
///        i += 1
///     return sync_committee_indices
pub fn getNextSyncCommitteeIndices(state: *consensus.BeaconState, allocator: std.mem.Allocator) ![]primitives.ValidatorIndex {
    const epoch = @as(primitives.Epoch, epoch_helper.getCurrentEpoch(state) + 1);
    const MAX_RANDOM_BYTE = std.math.maxInt(u8);

    const active_validator_indices = try validator_helper.getActiveValidatorIndices(state, epoch, allocator);
    defer allocator.free(active_validator_indices);
    const active_validator_count = @as(u64, active_validator_indices.len);
    const seed = seed_helper.getSeed(state, epoch, constants.DOMAIN_SYNC_COMMITTEE);

    // Fixed-size buffer allocation
    var result = try allocator.alloc(primitives.ValidatorIndex, preset.ActivePreset.get().SYNC_COMMITTEE_SIZE);
    var count: usize = 0;
    var i: usize = 0;

    while (count < preset.ActivePreset.get().SYNC_COMMITTEE_SIZE) {
        const shuffled_index = try shuffle_helper.computeShuffledIndex(@as(u64, @mod(i, active_validator_count)), active_validator_count, seed);
        const candidate_index = active_validator_indices[shuffled_index];
        const seed_origin = seed ++ std.mem.asBytes(&@as(u64, @divFloor(i, 32)));
        var seed_hash: primitives.Bytes32 = undefined;
        sha256.hash(seed_origin, &seed_hash, .{});
        const random_byte = seed_hash[@mod(i, 32)];
        const effective_balance = state.validators()[candidate_index].effective_balance;

        const max_effective_balance = if (state.* == .electra)
            preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE_ELECTRA
        else
            preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE;

        if (effective_balance * MAX_RANDOM_BYTE >= max_effective_balance * random_byte) {
            result[count] = candidate_index;
            count += 1;
        }
        i += 1;
    }
    return result;
}

test "test getCommitteeCountPerSlot" {
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

    for (0..500000) |_| {
        try validators.append(validator1);
        try validators.append(validator2);
    }

    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
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
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const count = try getCommitteeCountPerSlot(&state, @as(primitives.Epoch, 5), std.testing.allocator);
    try std.testing.expectEqual(
        4,
        count,
    );
}

test "test computeCommittee" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const indices = [_]primitives.ValidatorIndex{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const seed = .{1} ** 32;
    const index = 1;
    const count = 3;
    const committee = try computeCommittee(&indices, seed, index, count, std.testing.allocator);
    defer std.testing.allocator.free(committee);
    try std.testing.expectEqual(3, committee.len);
    try std.testing.expectEqual(9, committee[0]);
    try std.testing.expectEqual(0, committee[1]);
    try std.testing.expectEqual(8, committee[2]);
}

test "test getBeaconCommittee" {
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
    for (0..500000) |_| {
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

    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
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
            .balances = undefined,
            .randao_mixes = randao_mixes.items,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const committee = try getBeaconCommittee(&state, 100, 1, std.testing.allocator);
    defer std.testing.allocator.free(committee);
    try std.testing.expectEqual(15625, committee.len);
    try std.testing.expectEqual(341591, committee[0]);
    try std.testing.expectEqual(554849, committee[15624]);
}

test "test getBeaconProposerIndex" {
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
    for (0..500000) |_| {
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

    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
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
            .balances = undefined,
            .randao_mixes = randao_mixes.items,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const proposer_index = try getBeaconProposerIndex(&state, std.testing.allocator);
    try std.testing.expectEqual(674517, proposer_index);
}

test "test getNextSyncCommitteeIndices" {
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
    for (0..500000) |_| {
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

    var state = consensus.BeaconState{
        .altair = altair.BeaconState{
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
            .balances = undefined,
            .randao_mixes = randao_mixes.items,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const indices = try getNextSyncCommitteeIndices(&state, std.testing.allocator);
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqual(32, indices.len);
    try std.testing.expectEqual(864147, indices[0]);
    try std.testing.expectEqual(523537, indices[1]);
    try std.testing.expectEqual(260131, indices[2]);
    try std.testing.expectEqual(141919, indices[3]);
    try std.testing.expectEqual(693377, indices[4]);
}
