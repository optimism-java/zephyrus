const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const sha256 = std.crypto.hash.sha2.Sha256;

/// verifyMerkleProof verifies a merkle proof.
/// @param leaf - The leaf value.
/// @param branch - The branch.
/// @param depth - The depth.
/// @param index - The index.
/// @param root - The root.
/// @returns True if the proof is valid, false otherwise.
/// Spec pseudocode definition:
/// def is_valid_merkle_branch(leaf: Bytes32, branch: Sequence[Bytes32], depth: uint64, index: uint64, root: Root) -> bool:
///     """
///     Check if ``leaf`` at ``index`` verifies against the Merkle ``root`` and ``branch``.
///     """
///     value = leaf
///     for i in range(depth):
///         if index // (2**i) % 2:
///              value = hash(branch[i] + value)
///         else:
///              value = hash(value + branch[i])
///     return value == root
pub fn verifyMerkleProof(leaf: primitives.Bytes32, branch: []const primitives.Bytes32, depth: u64, index: u64, root: primitives.Root) !bool {
    var value: [32]u8 = leaf;
    var i: u64 = 0;
    while (i < depth) : (i += 1) {
        var combined: [64]u8 = undefined;
        if (@mod(try std.math.divFloor(u64, index, std.math.pow(u64, 2, i)), 2) != 0) {
            @memcpy(combined[0..32], &branch[i]);
            @memcpy(combined[32..64], &value);
        } else {
            @memcpy(combined[0..32], &value);
            @memcpy(combined[32..64], &branch[i]);
        }
        sha256.hash(&combined, &value, .{});
    }
    return std.mem.eql(u8, &value, &root);
}

test "verifyMerkleProof" {
    const leaf: primitives.Bytes32 = undefined;
    const branch: [32]primitives.Bytes32 = undefined;
    const root: primitives.Root = undefined;
    const depth: u64 = 0;
    const index: u64 = 0;
    try std.testing.expect(try verifyMerkleProof(leaf, &branch, depth, index, root));
}

test "verifyMerkleProof with valid branch" {
    const leaf: primitives.Bytes32 = [_]u8{1} ** 32;
    const branch: [32]primitives.Bytes32 = [_]primitives.Bytes32{[_]u8{2} ** 32} ** 32;
    const root: primitives.Root = [_]u8{ 228, 209, 245, 144, 152, 7, 227, 251, 129, 176, 248, 115, 30, 139, 1, 35, 21, 112, 168, 110, 176, 175, 25, 181, 52, 215, 85, 95, 22, 63, 166, 194 };
    const depth: u64 = 5;
    const index: u64 = 0;
    try std.testing.expect(try verifyMerkleProof(leaf, &branch, depth, index, root));
}
