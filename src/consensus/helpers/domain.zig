const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const ssz = @import("../../ssz/ssz.zig");

/// computeForkDataRoot return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
/// This is used primarily in signature domains to avoid collisions across forks/chains.
/// @param current_version The current fork version
/// @param genesis_validators_root The genesis validators root
/// @param allocator The allocator to use
/// @return The 32-byte fork data root
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
pub fn computeForkDataRoot(current_version: primitives.Version, genesis_validators_root: primitives.Root, allocator: std.mem.Allocator) !primitives.Root {
    const fork_data = consensus.ForkData{
        .current_version = current_version,
        .genesis_validators_root = genesis_validators_root,
    };

    std.log.debug("ForkData: {}\n", .{fork_data});
    var out: primitives.Root = undefined;
    try ssz.hashTreeRoot(fork_data, &out, allocator);
    return out;
}

/// computeForkDigest returns the 4-byte fork digest for the `currentVersion` and `genesisValidatorsRoot`.
/// This is a digest primarily used for domain separation on the p2p layer.
/// 4-bytes suffices for practical separation of forks/chains.
/// @param currentVersion The current fork version
/// @param genesisValidatorsRoot The genesis validators root
/// @param allocator The allocator to use
/// @return The 4-byte fork digest
/// Spec pseudocode definition:
/// def compute_fork_digest(current_version: Version, genesis_validators_root: Root) -> ForkDigest:
///    """
///    Return the 4-byte fork digest for the ``current_version`` and ``genesis_validators_root``.
///    This is a digest primarily used for domain separation on the p2p layer.
///    4-bytes suffices for practical separation of forks/chains.
///    """
///    return ForkDigest(compute_fork_data_root(current_version, genesis_validators_root)[:4])
pub fn computeForkDigest(currentVersion: primitives.Version, genesisValidatorsRoot: primitives.Root, allocator: std.mem.Allocator) !primitives.ForkDigest {
    const forkDataRoot = try computeForkDataRoot(currentVersion, genesisValidatorsRoot, allocator);
    return forkDataRoot[0..4].*;
}

/// computeDomain returns the domain for the ``domain_type`` and ``fork_version`` and ``genesis_validators_root``.
/// @param domain_type - The domain type.
/// @param fork_version - The fork version.
/// @param genesis_validators_root - The genesis validators root.
/// @param allocator - The allocator to use.
/// @return The domain.
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
pub fn computeDomain(domain_type: primitives.DomainType, fork_version: ?primitives.Version, genesis_validators_root: ?primitives.Root, allocator: std.mem.Allocator) !primitives.Domain {
    const DOMAIN_TYPE_LENGTH: usize = 4;
    const FORK_DATA_ROOT_LENGTH: usize = 28;

    const effective_fork_version = fork_version orelse configs.ActiveConfig.get().GENESIS_FORK_VERSION;
    const effective_genesis_validators_root = genesis_validators_root orelse @as(primitives.Root, .{0} ** 32);

    const fork_data_root = try computeForkDataRoot(effective_fork_version, effective_genesis_validators_root, allocator);

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
    const forkDigest =try computeForkDigest(currentVersion, genesisValidatorsRoot, std.testing.allocator);
    try std.testing.expectEqual(4, forkDigest.len);
}

test "test computeForkDataRoot" {
    const currentVersion = .{0} ** 4;
    const genesisValidatorsRoot = .{0} ** 32;
    const forkDataRoot =try computeForkDataRoot(currentVersion, genesisValidatorsRoot, std.testing.allocator);
    try std.testing.expectEqual(32, forkDataRoot.len);
}

test "test computeDomain" {
    const domainType = .{0} ** 4;
    const forkVersion = .{0} ** 4;
    const genesisValidatorsRoot = .{0} ** 32;
    const domain = try computeDomain(domainType, forkVersion, genesisValidatorsRoot, std.testing.allocator);
    try std.testing.expectEqual(32, domain.len);
}
