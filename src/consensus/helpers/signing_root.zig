const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const ssz = @import("../../ssz/ssz.zig");

/// computeSigningRoot returns the signing root for the ``sszObject`` and ``domain``.
/// Spec pseudocode definition:
/// def compute_signing_root(ssz_object: SSZObject, domain: Domain) -> Root:
///     """
///     Return the signing root for the corresponding signing data.
///     """
///    return hash_tree_root(SigningData(
///         object_root=hash_tree_root(ssz_object),
///         domain=domain,
///   ))
pub fn computeSigningRoot(sszObject: anytype, domain: primitives.Domain, allocator: std.mem.Allocator) !primitives.Root {
    var objectRoot: primitives.Root = undefined;
    try ssz.hashTreeRoot(sszObject, &objectRoot, allocator);
    const signingData = consensus.SigningData{
        .object_root = objectRoot,
        .domain = domain,
    };

    var out: primitives.Root = undefined;
    try ssz.hashTreeRoot(signingData, &out, allocator);
    return out;
}

test "test computeSigningRoot" {
    const domain = @as(primitives.Domain, .{0} ** 32);
    const forkData = consensus.ForkData{
        .current_version = @as(primitives.Version, .{0} ** 4),
        .genesis_validators_root = @as(primitives.Root, .{0} ** 32),
    };
    const signingRoot = computeSigningRoot(forkData, domain, std.testing.allocator);
    std.debug.print("signingRoot: {any}\n", .{signingRoot});
    try std.testing.expectEqual(signingRoot, .{ 122, 5, 1, 245, 149, 123, 223, 156, 179, 168, 255, 73, 102, 240, 34, 101, 249, 104, 101, 139, 122, 156, 98, 100, 44, 186, 17, 101, 232, 102, 66, 245 });
}
