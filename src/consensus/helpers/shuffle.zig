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
pub fn computeShuffledIndex(index: u64, index_count: u64, seed: *const primitives.Bytes32) !u64 {
    if (index >= index_count) return error.IndexOutOfBounds;

    var current_index = index;

    // Perform the shuffling algorithm
    for (@as(u64, 0)..preset.ActivePreset.get().SHUFFLE_ROUND_COUNT) |current_round| {
        // Generate round seed
        var round_seed: primitives.Bytes32 = undefined;
        sha256.hash(seed.* ++ &[_]u8{@as(u8, @intCast(current_round))}, &round_seed, .{});

        // Calculate pivot and flip
        const pivot = @mod(std.mem.readInt(u64, round_seed[0..8], .little), index_count);
        const flip = @mod((pivot + index_count - current_index), index_count);
        const position = @max(current_index, flip);

        // Generate source seed
        var source_seed: primitives.Bytes32 = undefined;
        const position_div_256 = @as(u32, @intCast(@divFloor(position, 256)));
        sha256.hash(seed.* ++ &[_]u8{@as(u8, @intCast(current_round))} ++ std.mem.toBytes(position_div_256), &source_seed, .{});

        // Determine bit value and update current_index
        const byte_index = @divFloor(@mod(position, 256), 8);
        const bit_index = @as(u3, @intCast(@mod(position, 8)));
        const selected_byte = source_seed[byte_index];
        const selected_bit = @mod(selected_byte >> bit_index, 2);

        current_index = if (selected_bit == 1) flip else current_index;
    }

    return current_index;
}

test "test computeShuffledIndex" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const index_count = 10;
    const seed = .{3} ** 32;
    const index = 5;
    const shuffledIndex = try computeShuffledIndex(index, index_count, &seed);
    try std.testing.expectEqual(7, shuffledIndex);

    const index_count1 = 10000000;
    const seed1 = .{4} ** 32;
    const index1 = 5776655;
    const shuffledIndex1 = try computeShuffledIndex(index1, index_count1, &seed1);
    try std.testing.expectEqual(3446028, shuffledIndex1);
}
