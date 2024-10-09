const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");

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
    std.crypto.hash.sha2.Sha256.hash(&input, &h, .{});
    return h;
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
