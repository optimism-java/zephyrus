const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const electra = @import("../../consensus/electra/types.zig");
const epoch_helper = @import("../../consensus/helpers/epoch.zig");
const shuffle_helper = @import("../../consensus/helpers/shuffle.zig");
const balance_helper = @import("../../consensus/helpers/balance.zig");
const committee_helper = @import("../../consensus/helpers/committee.zig");
const finality_helper = @import("../../consensus/helpers/finality.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");

pub fn getBaseReward(state: *const consensus.BeaconState, index: primitives.ValidatorIndex, allocator: std.mem.Allocator) !primitives.Gwei {
    const increments = state.validators()[index].effective_balance / preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT;
    const base_reward_per_increment = try getBaseRewardPerIncrement(state, allocator);
    return increments * base_reward_per_increment;
}

pub fn getBaseRewardPerIncrement(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !primitives.Gwei {
    const total_balance = try balance_helper.getTotalActiveBalance(state, allocator);
    const sqrt_balance = std.math.sqrt(total_balance);
    return @as(primitives.Gwei, @divFloor(preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT * preset.ActivePreset.get().BASE_REWARD_FACTOR, sqrt_balance));
}

pub fn getFlagIndexDeltas(state: *const consensus.BeaconState, flag_index: u3, allocator: std.mem.Allocator) !struct { []primitives.Gwei, []primitives.Gwei } {
    const rewards = try allocator.alloc(primitives.Gwei, state.validators().len);
    @memset(rewards, 0);
    var penalties = try allocator.alloc(primitives.Gwei, state.validators().len);
    @memset(penalties, 0);

    const previous_epoch = epoch_helper.getPreviousEpoch(state);
    const unslashed_participating_indices = try validator_helper.getUnslashedParticipatingIndices(state, flag_index, previous_epoch, allocator);
    defer allocator.free(unslashed_participating_indices);

    var unslashed_participating_indices_set = std.AutoHashMap(primitives.ValidatorIndex, void).init(allocator);
    defer unslashed_participating_indices_set.deinit();

    for (unslashed_participating_indices) |index| {
        try unslashed_participating_indices_set.put(index, {});
    }
    const weight = constants.PARTICIPATION_FLAG_WEIGHTS[flag_index];
    const unslashed_participating_balance = balance_helper.getTotalBalance(state, &unslashed_participating_indices_set);
    const unslashed_participating_increments = @divFloor(unslashed_participating_balance, preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT);
    const active_increments = @divFloor(try balance_helper.getTotalActiveBalance(state, allocator), preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT);

    const eligible_indices = try validator_helper.getEligibleValidatorIndices(state, allocator);
    defer allocator.free(eligible_indices);
    for (eligible_indices) |index| {
        const base_reward = try getBaseReward(state, index, allocator);

        if (std.mem.containsAtLeast(primitives.ValidatorIndex, unslashed_participating_indices, 1, &[_]primitives.ValidatorIndex{index})) {
            if (!finality_helper.isInInactivityLeak(state)) {
                const reward_numerator = base_reward * weight * unslashed_participating_increments;
                rewards[index] += @divFloor(reward_numerator, (active_increments * constants.WEIGHT_DENOMINATOR));
            }
        } else if (flag_index != constants.TIMELY_HEAD_FLAG_INDEX) {
            penalties[index] += @divFloor(base_reward * weight, constants.WEIGHT_DENOMINATOR);
        }
    }

    return .{ rewards, penalties };
}

// todo: need to add phase0 logic
pub fn getInactivityPenaltyDeltas(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !struct { []primitives.Gwei, []primitives.Gwei } {
    const rewards = try allocator.alloc(primitives.Gwei, state.validators().len);
    @memset(rewards, 0);
    var penalties = try allocator.alloc(primitives.Gwei, state.validators().len);
    @memset(penalties, 0);

    const previous_epoch = epoch_helper.getPreviousEpoch(state);
    const matching_target_indices = try validator_helper.getUnslashedParticipatingIndices(state, constants.TIMELY_TARGET_FLAG_INDEX, previous_epoch, allocator);
    defer allocator.free(matching_target_indices);

    const eligible_indices = try validator_helper.getEligibleValidatorIndices(state, allocator);
    for (eligible_indices) |index| {
        if (!std.mem.containsAtLeast(primitives.ValidatorIndex, matching_target_indices, 1, &[_]primitives.ValidatorIndex{index})) {
            const penalty_numerator = state.validators()[index].effective_balance *
                state.inactivityScores()[index];
            const state_enum = @intFromEnum(state.*);
            const is_bellatrix_or_later = state_enum >= @intFromEnum(primitives.ForkType.bellatrix);
            const penalty_quotient: u64 = if (is_bellatrix_or_later)
                preset.ActivePreset.get().INACTIVITY_PENALTY_QUOTIENT_BELLATRIX
            else
                preset.ActivePreset.get().INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
            const penalty_denominator = configs.ActiveConfig.get().INACTIVITY_SCORE_BIAS *
                penalty_quotient;
            penalties[index] = @divFloor(penalty_numerator, penalty_denominator);
        }
    }

    return .{ rewards, penalties };
}

// todo: need to add phase0 logic
pub fn processRewardsAndPenalties(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !void {
    // No rewards at GENESIS_EPOCH since rewards are for previous epoch work
    if (epoch_helper.getCurrentEpoch(state) == constants.GENESIS_EPOCH) {
        return;
    }

    var flag_deltas = std.ArrayList(struct { []u64, []u64 }).init(allocator);
    defer flag_deltas.deinit();

    // Get deltas for each flag index
    var i: usize = 0;
    while (i < constants.PARTICIPATION_FLAG_WEIGHTS.len) : (i += 1) {
        const deltas = try getFlagIndexDeltas(state, @intCast(i), allocator);
        try flag_deltas.append(deltas);
    }

    // Add inactivity penalties
    const inactivity_deltas = try getInactivityPenaltyDeltas(state, allocator);
    try flag_deltas.append(inactivity_deltas);

    // Apply all deltas
    for (flag_deltas.items) |delta| {
        var index: usize = 0;
        while (index < state.validators().len) : (index += 1) {
            balance_helper.increaseBalance(state, index, delta.@"0"[index]);
            balance_helper.decreaseBalance(state, index, delta.@"1"[index]);
        }
    }
}
