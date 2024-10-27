const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");
const phase0 = @import("../../consensus/phase0/types.zig");

pub const LightClientHeader = struct {
    beacon: consensus.BeaconBlockHeader,
};

pub const LightClientOptimisticUpdate = struct {
    attested_header: consensus.LightClientHeader,
    sync_aggregate: consensus.SyncAggregate,
    signature_slot: primitives.Slot,
};

pub const LightClientFinalityUpdate = struct {
    attested_header: consensus.LightClientHeader,
    finalized_header: consensus.LightClientHeader,
    finality_branch: primitives.FinalityBranch,
    sync_aggregate: consensus.SyncAggregate,
    signature_slot: primitives.Slot,
};

pub const LightClientUpdate = struct {
    attested_header: consensus.LightClientHeader,
    next_sync_committee: consensus.SyncCommittee,
    next_sync_committee_branch: primitives.NextSyncCommitteeBranch,
    finalized_header: consensus.LightClientHeader,
    finality_branch: primitives.FinalityBranch,
    sync_aggregate: consensus.SyncAggregate,
    signature_slot: primitives.Slot,
};

pub const LightClientBootstrap = struct {
    header: consensus.LightClientHeader,
    current_sync_committee: consensus.SyncCommittee,
    current_sync_committee_branch: primitives.CurrentSyncCommitteeBranch,
};

pub const SignedVoluntaryExit = struct {
    message: consensus.VoluntaryExit,
    signature: primitives.BLSSignature,
};

pub const SyncAggregate = struct {
    sync_committee_bits: []bool,
    sync_committee_signature: primitives.BLSSignature,
};

pub const SyncCommittee = struct {
    pubkeys: []primitives.BLSPubkey,
    aggregate_pubkey: primitives.BLSPubkey,

    pub fn init(pubkeys: []primitives.BLSPubkey, aggregate_pubkey: primitives.BLSPubkey) SyncCommittee {
        return SyncCommittee{ .pubkeys = pubkeys, .aggregate_pubkey = aggregate_pubkey };
    }
};

pub const SyncCommitteeMessage = struct {
    slot: primitives.Slot,
    beacon_block_root: primitives.Root,
    validator_index: primitives.ValidatorIndex,
    signature: primitives.BLSSignature,
};

pub const SyncCommitteeContribution = struct {
    slot: primitives.Slot,
    beacon_block_root: primitives.Root,
    subcommittee_index: u64,
    aggregation_bits: []bool,
    signature: primitives.BLSSignature,
};

pub const ContributionAndProof = struct {
    aggregator_index: primitives.ValidatorIndex,
    contribution: consensus.SyncCommitteeContribution,
    selection_proof: primitives.BLSSignature,
};

pub const SignedContributionAndProof = struct {
    message: consensus.ContributionAndProof,
    signature: primitives.BLSSignature,
};

pub const BeaconBlockBody = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(phase0.BeaconBlockBody).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "sync_aggregate",
                    .type = consensus.SyncAggregate,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(consensus.SyncAggregate),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const BeaconState = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(phase0.BeaconState).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "inactivity_scores",
                    .type = []u64,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]u64),
                },
                .{
                    .name = "current_sync_committee",
                    .type = consensus.SyncCommittee,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(consensus.SyncCommittee),
                },
                .{
                    .name = "next_sync_committee",
                    .type = consensus.SyncCommittee,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf(consensus.SyncCommittee),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

test "test BeaconState" {
    const state = BeaconState{
        .genesis_time = 0,
        .genesis_validators_root = undefined,
        .slot = 0,
        .fork = undefined,
        .latest_block_header = undefined,
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
        .inactivity_scores = undefined,
        .current_sync_committee = undefined,
        .next_sync_committee = undefined,
    };

    try std.testing.expectEqual(state.genesis_time, 0);
}

test "test BeaconBlockBody" {
    const body = BeaconBlockBody{
        .randao_reveal = undefined,
        .eth1_data = undefined,
        .graffiti = undefined,
        .proposer_slashings = undefined,
        .attester_slashings = undefined,
        .attestations = undefined,
        .deposits = undefined,
        .voluntary_exits = undefined,
        .sync_aggregate = undefined,
    };

    try std.testing.expectEqual(body.randao_reveal.len, 96);
}

test "test SignedVoluntaryExit" {
    const exit = SignedVoluntaryExit{
        .message = undefined,
        .signature = undefined,
    };

    try std.testing.expectEqual(exit.message, undefined);
}

test "test SyncAggregate" {
    const aggregate = SyncAggregate{
        .sync_committee_bits = &[_]bool{},
        .sync_committee_signature = undefined,
    };

    try std.testing.expectEqual(aggregate.sync_committee_bits.len, 0);
}

test "test SyncCommittee" {
    const committee = SyncCommittee{
        .pubkeys = &[_]primitives.BLSPubkey{},
        .aggregate_pubkey = undefined,
    };

    try std.testing.expectEqual(committee.pubkeys.len, 0);
}

test "test SyncCommitteeMessage" {
    const message = SyncCommitteeMessage{
        .slot = 0,
        .beacon_block_root = undefined,
        .validator_index = 0,
        .signature = undefined,
    };

    try std.testing.expectEqual(message.slot, 0);
}

test "test SyncCommitteeContribution" {
    const contribution = SyncCommitteeContribution{
        .slot = 0,
        .beacon_block_root = undefined,
        .subcommittee_index = 0,
        .aggregation_bits = &[_]bool{},
        .signature = undefined,
    };

    try std.testing.expectEqual(contribution.slot, 0);
}

test "test ContributionAndProof" {
    const contribution = ContributionAndProof{
        .aggregator_index = 0,
        .contribution = undefined,
        .selection_proof = undefined,
    };

    try std.testing.expectEqual(contribution.aggregator_index, 0);
}

test "test SignedContributionAndProof" {
    const contribution = SignedContributionAndProof{
        .message = undefined,
        .signature = undefined,
    };

    try std.testing.expectEqual(contribution.message, undefined);
}

test "test LightClientHeader" {
    const header = LightClientHeader{
        .beacon = undefined,
    };

    try std.testing.expectEqual(header.beacon, undefined);
}

test "test LightClientOptimisticUpdate" {
    const update = LightClientOptimisticUpdate{
        .attested_header = undefined,
        .sync_aggregate = undefined,
        .signature_slot = 0,
    };

    try std.testing.expectEqual(update.attested_header, undefined);
    try std.testing.expectEqual(update.sync_aggregate, undefined);
    try std.testing.expectEqual(update.signature_slot, 0);
}

test "test LightClientFinalityUpdate" {
    const finality_branch = primitives.FinalityBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 6,
    };

    const update = LightClientFinalityUpdate{
        .attested_header = undefined,
        .finalized_header = undefined,
        .finality_branch = finality_branch,
        .sync_aggregate = undefined,
        .signature_slot = 0,
    };

    try std.testing.expectEqual(update.attested_header, undefined);
    try std.testing.expectEqual(update.finalized_header, undefined);
    try std.testing.expect(update.finality_branch.altair.len == 6);
    try std.testing.expectEqual(update.sync_aggregate, undefined);
    try std.testing.expectEqual(update.signature_slot, 0);
}

test "test LightClientUpdate" {
    const next_sync_committee_branch = primitives.NextSyncCommitteeBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 5,
    };

    const finality_branch = primitives.FinalityBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 6,
    };

    const update = LightClientUpdate{
        .attested_header = undefined,
        .next_sync_committee = undefined,
        .next_sync_committee_branch = next_sync_committee_branch,
        .finalized_header = undefined,
        .finality_branch = finality_branch,
        .sync_aggregate = undefined,
        .signature_slot = 0,
    };

    try std.testing.expectEqual(update.attested_header, undefined);
    try std.testing.expectEqual(update.next_sync_committee, undefined);
    try std.testing.expect(update.next_sync_committee_branch.altair.len == 5);
    try std.testing.expectEqual(update.finalized_header, undefined);
    try std.testing.expect(update.finality_branch.altair.len == 6);
    try std.testing.expectEqual(update.sync_aggregate, undefined);
    try std.testing.expectEqual(update.signature_slot, 0);
}

test "test LightClientBootstrap" {
    const current_sync_committee_branch = primitives.CurrentSyncCommitteeBranch{
        .altair = [_][32]u8{
            [_]u8{0} ** 32,
        } ** 5,
    };

    const bootstrap = LightClientBootstrap{
        .header = undefined,
        .current_sync_committee = undefined,
        .current_sync_committee_branch = current_sync_committee_branch,
    };

    try std.testing.expectEqual(bootstrap.header, undefined);
    try std.testing.expectEqual(bootstrap.current_sync_committee, undefined);
    try std.testing.expect(bootstrap.current_sync_committee_branch.altair.len == 5);
}
