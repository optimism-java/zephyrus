const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const altair = @import("../../consensus/altair/types.zig");
const preset = @import("../../presets/preset.zig");
const epoch_helper = @import("./epoch.zig");
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

/// getDomain returns the domain for the ``domain_type`` and ``epoch``.
/// @param state - The state.
/// @param domain_type - The domain type.
/// @param epoch - The epoch.
/// @returns The domain.
/// Spec pseudocode definition:
/// def get_domain(state: BeaconState, domain_type: DomainType, epoch: Epoch=None) -> Domain:
///    """
///    Return the signature domain (fork version concatenated with domain type) of a message.
///   """
///   epoch = get_current_epoch(state) if epoch is None else epoch
///   fork_version = state.fork.previous_version if epoch < state.fork.epoch else state.fork.current_version
///   return compute_domain(domain_type, fork_version, state.genesis_validators_root)
pub fn getDomain(state: *const consensus.BeaconState, domainType: primitives.DomainType, epoch: ?primitives.Epoch, allocator: std.mem.Allocator) !primitives.Domain {
    const current_epoch = epoch orelse epoch_helper.getCurrentEpoch(state);
    const fork_version = if (current_epoch < state.fork().epoch) state.fork().previous_version else state.fork().current_version;
    return try computeDomain(domainType, fork_version, state.genesisValidatorsRoot(), allocator);
}

test "test computeForkDigest" {
    const currentVersion = .{3} ** 4;
    const genesisValidatorsRoot = .{2} ** 32;
    const forkDigest = try computeForkDigest(currentVersion, genesisValidatorsRoot, std.testing.allocator);
    try std.testing.expectEqual(4, forkDigest.len);
    try std.testing.expectEqual([4]u8{ 164, 100, 54, 186 }, forkDigest);
}

test "test computeForkDataRoot" {
    const currentVersion = .{0} ** 4;
    const genesisValidatorsRoot = .{0} ** 32;
    const forkDataRoot = try computeForkDataRoot(currentVersion, genesisValidatorsRoot, std.testing.allocator);
    try std.testing.expectEqual(32, forkDataRoot.len);
    try std.testing.expectEqual([32]u8{ 245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75 }, forkDataRoot);
}

test "test computeDomain" {
    const domainType = .{2} ** 4;
    const forkVersion = .{4} ** 4;
    const genesisValidatorsRoot = .{5} ** 32;
    const domain = try computeDomain(domainType, forkVersion, genesisValidatorsRoot, std.testing.allocator);
    try std.testing.expectEqual(32, domain.len);
    try std.testing.expectEqual([32]u8{ 2, 2, 2, 2, 32, 125, 236, 13, 25, 22, 206, 134, 1, 218, 218, 156, 241, 61, 204, 254, 64, 74, 66, 44, 6, 212, 31, 140, 234, 29, 169, 68 }, domain);
}

test "test getDomain" {
    configs.ActiveConfig.set(preset.Presets.minimal);
    defer configs.ActiveConfig.reset();
    const state = consensus.BeaconState{
        .altair = altair.BeaconState{
            .genesis_time = 0,
            .genesis_validators_root = .{8} ** 32,
            .slot = 100,
            .fork = consensus.Fork{
                .previous_version = .{0} ** 4,
                .current_version = .{1} ** 4,
                .epoch = 10,
            },
            .block_roots = undefined,
            .state_roots = undefined,
            .historical_roots = undefined,
            .eth1_data = undefined,
            .eth1_data_votes = undefined,
            .eth1_deposit_index = 0,
            .validators = undefined,
            .balances = undefined,
            .randao_mixes = undefined,
            .slashings = undefined,
            .previous_epoch_attestations = undefined,
            .current_epoch_attestations = undefined,
            .justification_bits = undefined,
            .previous_justified_checkpoint = undefined,
            .current_justified_checkpoint = undefined,
            .finalized_checkpoint = undefined,
            .latest_block_header = undefined,
            .inactivity_scores = undefined,
            .current_sync_committee = undefined,
            .next_sync_committee = undefined,
        },
    };
    const domainType = .{3} ** 4;
    const domain = try getDomain(&state, domainType, 5, std.testing.allocator);
    try std.testing.expectEqual(32, domain.len);
    try std.testing.expectEqual([32]u8{ 3, 3, 3, 3, 61, 113, 193, 5, 44, 77, 156, 103, 107, 126, 246, 245, 190, 212, 101, 12, 208, 96, 214, 77, 178, 157, 214, 159, 250, 25, 45, 56 }, domain);
}
