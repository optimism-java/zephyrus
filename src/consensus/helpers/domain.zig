const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");

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
    return @as(primitives.Root, .{0} ** 32);
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

/// computeDomain returns the domain for the ``domain_type`` and ``fork_version`` and ``genesis_validators_root``.
/// Spec pseudocode definition:
/// def compute_domain(domain_type: DomainType, fork_version: Version=None, genesis_validators_root: Root=None) -> Domain:
///    """
///    Return the domain for the ``domain_type`` and ``fork_version``.
///    """
///    if fork_version is None:
///       fork_version = config.GENESIS_FORK_VERSION
///    if genesis_validators_root is None:
///       genesis_validators_root = Root()  # all bytes zero by default
///    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
///    return Domain(domain_type + fork_data_root[:28])
pub fn computeDomain(domain_type: primitives.DomainType, fork_version: ?primitives.Version, genesis_validators_root: ?primitives.Root) primitives.Domain {
    const DOMAIN_TYPE_LENGTH: usize = 4;
    const FORK_DATA_ROOT_LENGTH: usize = 28;

    const effective_fork_version = fork_version orelse configs.ActiveConfig.get().GENESIS_FORK_VERSION;
    const effective_genesis_validators_root = genesis_validators_root orelse @as(primitives.Root, .{0} ** 32);

    const fork_data_root = computeForkDataRoot(effective_fork_version, effective_genesis_validators_root);

    const result = blk: {
        var temp: primitives.Domain = undefined;
        @memcpy(temp[0..DOMAIN_TYPE_LENGTH], &domain_type);
        @memcpy(temp[DOMAIN_TYPE_LENGTH..], fork_data_root[0..FORK_DATA_ROOT_LENGTH]);
        break :blk temp;
    };

    return result;
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

test "test computeDomain" {
    const domainType = .{0} ** 4;
    const forkVersion = .{0} ** 4;
    const genesisValidatorsRoot = .{0} ** 32;
    const domain = computeDomain(domainType, forkVersion, genesisValidatorsRoot);
    try std.testing.expectEqual(32, domain.len);
}
