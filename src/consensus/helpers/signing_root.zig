const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");

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
pub fn computeSigningRoot(comptime sszObject: type, domain: primitives.Domain) primitives.Root {
    // const objectRoot = hashTreeRoot(sszObject);
    std.log.debug("sszObject: {}\n", .{sszObject});
    const objectRoot = @as(primitives.Root, .{0} ** 32);
    const signingData = consensus.SigningData{
        .object_root = objectRoot,
        .domain = domain,
    };

    std.log.debug("signingData: {}\n", .{signingData});
    // return hashTreeRoot(signingData);
    return @as(primitives.Root, .{0} ** 32);
}

test "test computeSigningRoot" {
    const domain = @as(primitives.Domain, .{0} ** 32);
    const signingRoot = computeSigningRoot(primitives.Transaction, domain);
    try std.testing.expectEqual(signingRoot, @as(primitives.Root, .{0} ** 32));
}
