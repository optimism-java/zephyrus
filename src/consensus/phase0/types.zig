const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");

pub const Attestation = struct {
    aggregation_bits: []bool,
    data: consensus.AttestationData,
    signature: primitives.BLSSignature,
};

pub const BeaconBlockBody = struct {
    randao_reveal: primitives.BLSSignature,
    eth1_data: consensus.Eth1Data, // Eth1 data vote
    graffiti: primitives.Bytes32, // Arbitrary data
    // Operations
    proposer_slashings: []consensus.ProposerSlashing,
    attester_slashings: []consensus.AttesterSlashing,
    attestations: []consensus.Attestation,
    deposits: []consensus.Deposit,
    voluntary_exits: []consensus.SignedVoluntaryExit,
};

pub const BeaconState = struct {
    genesis_time: u64,
    genesis_validators_root: primitives.Root,
    slot: primitives.Slot,
    fork: consensus.Fork,
    latest_block_header: consensus.BeaconBlockHeader,
    block_roots: []primitives.Root,
    state_roots: []primitives.Root,
    historical_roots: []primitives.Root,
    eth1_data: consensus.Eth1Data,
    eth1_data_votes: []consensus.Eth1Data,
    eth1_deposit_index: u64,
    validators: []consensus.Validator,
    balances: []primitives.Gwei,
    randao_mixes: []primitives.Bytes32,
    slashings: []primitives.Gwei,
    previous_epoch_attestations: []consensus.PendingAttestation,
    current_epoch_attestations: []consensus.PendingAttestation,
    justification_bits: []bool,
    previous_justified_checkpoint: consensus.Checkpoint,
    current_justified_checkpoint: consensus.Checkpoint,
    finalized_checkpoint: consensus.Checkpoint,
};

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
    };

    try std.testing.expectEqual(body.randao_reveal.len, 96);
}

test "test Attestation" {
    const attestation = Attestation{
        .aggregation_bits = &[_]bool{},
        .data = undefined,
        .signature = undefined,
    };

    try std.testing.expectEqual(attestation.aggregation_bits.len, 0);
}
