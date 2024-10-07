const zabi = @import("zabi");
const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");

/// computeForkDataRoot return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
/// This is used primarily in signature domains to avoid collisions across forks/chains.
/// Spec pseudocode definition:
/// def compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root:
///     """
///     Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
///     This is used primarily in signature domains to avoid collisions across forks/chains.
///     """
///    return hash_tree_root(ForkData(
///        current_version=current_version,
///        genesis_validators_root=genesis_validators_root,
///   ))
pub fn computeForkDataRoot(current_version: primitives.Version, genesis_validators_root: primitives.Root) primitives.Root {
    const fork_data = consensus.ForkData{
        .current_version = current_version,
        .genesis_validators_root = genesis_validators_root,
    };

    std.debug.print("ForkData: {}\n", .{fork_data});
    // todo: implement hash_tree_root
    return .{0} ** 32;
}

/// computeForkDigest returns the 4-byte fork digest for the `currentVersion` and `genesisValidatorsRoot`.
/// This is a digest primarily used for domain separation on the p2p layer.
/// 4-bytes suffices for practical separation of forks/chains.
/// Spec pseudocode definition:
/// def compute_fork_digest(current_version: Version, genesis_validators_root: Root) -> ForkDigest:
///    """
///    Return the 4-byte fork digest for the ``current_version`` and ``genesis_validators_root``.
///    This is a digest primarily used for domain separation on the p2p layer.
///    4-bytes suffices for practical separation of forks/chains.
///    """
///    return ForkDigest(compute_fork_data_root(current_version, genesis_validators_root)[:4])
pub fn computeForkDigest(currentVersion: primitives.Version, genesisValidatorsRoot: primitives.Root) primitives.ForkDigest {
    const forkDataRoot = computeForkDataRoot(currentVersion, genesisValidatorsRoot);
    return forkDataRoot[0..4].*;
}

test "test computeForkDigest" {
    const currentVersion = .{0} ** 4;
    const genesisValidatorsRoot = .{0} ** 32;
    const forkDigest = computeForkDigest(currentVersion, genesisValidatorsRoot);
    try std.testing.expectEqual(4, forkDigest.len);
}

test "test computeForkDataRoot" {
    const currentVersion = .{0} ** 4;
    const genesisValidatorsRoot = .{0} ** 32;
    const forkDataRoot = computeForkDataRoot(currentVersion, genesisValidatorsRoot);
    try std.testing.expectEqual(32, forkDataRoot.len);
}
