const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const sha256 = std.crypto.hash.sha2.Sha256;

/// getRandaoMix returns the randao mix at the given epoch.
/// @param state - The state.
/// @param epoch - The epoch.
/// @returns The randao mix at the given epoch.
/// Spec pseudocode definition:
/// def get_randao_mix(state: BeaconState, epoch: Epoch) -> Bytes32:
///    """
///    Return the randao mix at a recent ``epoch``.
///    """
///    return state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR]
pub fn getRandaoMix(state: *const consensus.BeaconState, epoch: primitives.Epoch) primitives.Bytes32 {
    return state.randaoMixes()[@mod(epoch, preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR)];
}

/// getSeed returns the seed at the given epoch.
/// @param state - The state.
/// @param epoch - The epoch.
/// @param domainType - The domain type.
/// @returns The seed at the given epoch.
/// Spec pseudocode definition:
/// def get_seed(state: BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32:
///     """
///     Return the seed at ``epoch``.
///     """
///     mix = get_randao_mix(state, Epoch(epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1))  # Avoid underflow
///     return hash(domain_type + uint_to_bytes(epoch) + mix)
pub fn getSeed(state: *const consensus.BeaconState, epoch: primitives.Epoch, domainType: primitives.DomainType) primitives.Bytes32 {
    const mix = getRandaoMix(state, @as(primitives.Epoch, @as(u64, epoch) + preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR - preset.ActivePreset.get().MIN_SEED_LOOKAHEAD - 1));
    var input = [_]u8{undefined} ** (primitives.DomainTypeSize + primitives.EpochSize + primitives.Bytes32Size);
    @memcpy(input[0..primitives.DomainTypeSize], &domainType);
    std.mem.writeInt(primitives.Epoch, input[primitives.DomainTypeSize .. primitives.DomainTypeSize + primitives.EpochSize], epoch, .little);
    @memcpy(input[primitives.DomainTypeSize + primitives.EpochSize ..], &mix);
    var h: primitives.Bytes32 = undefined;
    sha256.hash(&input, &h, .{});
    return h;
}

/// computeShuffledIndex returns the shuffled index.
/// @param index - The index.
/// @param index_count - The index count.
/// @param seed - The seed.
/// @returns The shuffled index.
/// Spec pseudocode definition:
/// def compute_shuffled_index(index: uint64, index_count: uint64, seed: Bytes32) -> uint64:
///    """
///    Return the shuffled index corresponding to ``seed`` (and ``index_count``).
///    """
///    assert index < index_count
///
///    # Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
///    # See the 'generalized domain' algorithm on page 3
///   for current_round in range(SHUFFLE_ROUND_COUNT):
///       pivot = bytes_to_uint64(hash(seed + uint_to_bytes(uint8(current_round)))[0:8]) % index_count
///      flip = (pivot + index_count - index) % index_count
///      position = max(index, flip)
///      source = hash(
///          seed
///          + uint_to_bytes(uint8(current_round))
///          + uint_to_bytes(uint32(position // 256))
///     )
///     byte = uint8(source[(position % 256) // 8])
///     bit = (byte >> (position % 8)) % 2
///     index = flip if bit else index
///
///     return index
pub fn computeShuffledIndex(index: u64, index_count: u64, seed: primitives.Bytes32) !u64 {
    if (index >= index_count) return error.IndexOutOfBounds;

    var current_index = index;

    // Perform the shuffling algorithm
    for (@as(u64, 0)..preset.ActivePreset.get().SHUFFLE_ROUND_COUNT) |current_round| {
        // Generate round seed
        var round_seed: primitives.Bytes32 = undefined;
        sha256.hash(seed ++ &[_]u8{@as(u8, @intCast(current_round))}, &round_seed, .{});

        // Calculate pivot and flip
        const pivot = @mod(std.mem.readInt(u64, round_seed[0..8], .little), index_count);
        const flip = @mod((pivot + index_count - current_index), index_count);
        const position = @max(current_index, flip);

        // Generate source seed
        var source_seed: primitives.Bytes32 = undefined;
        const position_div_256 = @as(u32, @intCast(@divFloor(position, 256)));
        sha256.hash(seed ++ &[_]u8{@as(u8, @intCast(current_round))} ++ std.mem.toBytes(position_div_256), &source_seed, .{});

        // Determine bit value and update current_index
        const byte_index = @divFloor(@mod(position, 256), 8);
        const bit_index = @as(u3, @intCast(@mod(position, 8)));
        const selected_byte = source_seed[byte_index];
        const selected_bit = @mod(selected_byte >> bit_index, 2);

        current_index = if (selected_bit == 1) flip else current_index;
    }

    return current_index;
}

pub fn computeProposerIndex(state: *const consensus.BeaconState, indices: []const primitives.ValidatorIndex, seed: primitives.Bytes32) !primitives.ValidatorIndex {
    if (indices.len == 0) return error.EmptyValidatorIndices;
    const MAX_RANDOM_BYTE: u8 = std.math.maxInt(u8);
    var i: u64 = 0;
    const total: u64 = indices.len;

    while (true) {
        const shuffled_index = try computeShuffledIndex(@mod(i, total), total, seed);
        const candidate_index = indices[@intCast(shuffled_index)];
        var hash_result: [32]u8 = undefined;
        var seed_plus: [40]u8 = undefined;
        @memcpy(seed_plus[0..32], &seed);
        std.mem.writeInt(u64, seed_plus[32..40], @divFloor(i, 32), .little);
        std.debug.print("seed_plus: {any}, i: {}\n", .{ seed_plus, i });
        std.crypto.hash.sha2.Sha256.hash(&seed_plus, &hash_result, .{});
        const randomByte = hash_result[@mod(i, 32)];
        const effectiveBalance = state.validators()[candidate_index].effective_balance;

        const max_effective_balance = switch (state.*) {
            .electra => preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE_ELECTRA,
            else => preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE,
        };
        if (effectiveBalance * MAX_RANDOM_BYTE >= max_effective_balance * randomByte) {
            return candidate_index;
        }
        i += 1;
    }
}

test "test get_randao_mix" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    var finalized_checkpoint = consensus.Checkpoint{
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
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator1);

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
            .block_roots = undefined,
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
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const randaoMix = getRandaoMix(&state, 0);
    try std.testing.expectEqual(randaoMix, .{0} ** 32);

    const randaoMix2 = getRandaoMix(&state, 1);
    try std.testing.expectEqual(randaoMix2, .{1} ** 32);

    const randaoMix3 = getRandaoMix(&state, 23);
    try std.testing.expectEqual(randaoMix3, .{23} ** 32);
}

test "test get_seed" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    var finalized_checkpoint = consensus.Checkpoint{
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
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator1);
    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 0,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator2);

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
            .block_roots = undefined,
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
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const seed = getSeed(&state, 0, .{0} ** 4);
    var expectedSeed: primitives.Bytes32 = undefined;
    const expected_value = [_]u8{0} ** 4 ++ [_]u8{0} ** 8 ++ [_]u8{62} ** 32;
    std.crypto.hash.sha2.Sha256.hash(&expected_value, &expectedSeed, .{});
    try std.testing.expectEqual(expectedSeed, seed);
}

test "test computeShuffledIndex" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const index_count = 10;
    const seed = .{3} ** 32;
    const index = 5;
    const shuffledIndex = try computeShuffledIndex(index, index_count, seed);
    try std.testing.expectEqual(7, shuffledIndex);

    const index_count1 = 10000000;
    const seed1 = .{4} ** 32;
    const index1 = 5776655;
    const shuffledIndex1 = try computeShuffledIndex(index1, index_count1, seed1);
    try std.testing.expectEqual(3446028, shuffledIndex1);
}

test "test computeProposerIndex" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    var finalized_checkpoint = consensus.Checkpoint{
        .epoch = 5,
        .root = .{0} ** 32,
    };
    var validators = std.ArrayList(consensus.Validator).init(std.testing.allocator);
    defer validators.deinit();
    const validator1 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 12312312312,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator1);
    const validator2 = consensus.Validator{
        .pubkey = undefined,
        .withdrawal_credentials = undefined,
        .effective_balance = 232323232332,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 0,
        .withdrawable_epoch = 0,
    };
    try validators.append(validator2);

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
            .block_roots = undefined,
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
            .finalized_checkpoint = &finalized_checkpoint,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };

    const validator_index = [_]primitives.ValidatorIndex{ 0, 1 };
    const proposer_index = try computeProposerIndex(&state, &validator_index, .{1} ** 32);
    try std.testing.expectEqual(0, proposer_index);
}
