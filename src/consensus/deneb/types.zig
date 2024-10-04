const std = @import("std");
pub const primitives = @import("../../primitives/types.zig");
const preset = @import("../../presets/preset.zig");
const consensus = @import("../../consensus/types.zig");
const capella = @import("../../consensus/capella/types.zig");

pub const BlobIdentifier = struct {
    block_root: primitives.Root,
    index: primitives.BlobIndex,
};

pub const BlobSidecar = struct {
    index: primitives.BlobIndex,
    blob: primitives.Blob,
    kzg_commitment: primitives.KZGCommitment,
    kzg_proof: primitives.KZGProof,
    signed_block_header: ?*consensus.SignedBeaconBlockHeader,
    kzg_commitment_inclusion_proof: []primitives.Bytes32,
};

pub const ExecutionPayload = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(capella.ExecutionPayload).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "blob_gas_used",
                    .type = u64,
                    .default_value = @ptrCast(&@as(u64, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(u64),
                },
                .{
                    .name = "excess_blob_gas",
                    .type = u64,
                    .default_value = @ptrCast(&@as(u64, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(u64),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const ExecutionPayloadHeader = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(capella.ExecutionPayloadHeader).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "blob_gas_used",
                    .type = u64,
                    .default_value = @ptrCast(&@as(u64, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(u64),
                },
                .{
                    .name = "excess_blob_gas",
                    .type = u64,
                    .default_value = @ptrCast(&@as(u64, 0)),
                    .is_comptime = false,
                    .alignment = @alignOf(u64),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

pub const BeaconBlockBody = @Type(
    .{
        .@"struct" = .{
            .layout = .auto,
            .fields = @typeInfo(capella.BeaconBlockBody).@"struct".fields ++ &[_]std.builtin.Type.StructField{
                .{
                    .name = "blob_kzg_commitments",
                    .type = []primitives.KZGCommitment,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = @alignOf([]primitives.KZGCommitment),
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    },
);

test "test ExecutionPayloadHeader" {
    const header = ExecutionPayloadHeader{
        .parent_hash = undefined,
        .fee_recipient = undefined,
        .state_root = undefined,
        .receipts_root = undefined,
        .logs_bloom = undefined,
        .prev_randao = undefined,
        .block_number = 21,
        .gas_used = 0,
        .gas_limit = 0,
        .timestamp = 0,
        .extra_data = undefined,
        .base_fee_per_gas = 0,
        .block_hash = undefined,
        .transactions_root = undefined,
        .withdrawals_root = undefined,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };

    try std.testing.expectEqual(header.parent_hash.len, 32);
    try std.testing.expectEqual(header.block_number, 21);
}

test "test ExecutionPayload" {
    const payload = ExecutionPayload{
        .parent_hash = undefined,
        .fee_recipient = undefined,
        .state_root = undefined,
        .receipts_root = undefined,
        .logs_bloom = undefined,
        .prev_randao = undefined,
        .block_number = 21,
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = undefined,
        .base_fee_per_gas = 0,
        .block_hash = undefined,
        .transactions = undefined,
        .withdrawals = undefined,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };

    try std.testing.expectEqual(payload.parent_hash.len, 32);
    try std.testing.expectEqual(payload.block_number, 21);
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
        .execution_payload = undefined,
        .bls_to_execution_changes = undefined,
        .blob_kzg_commitments = undefined,
    };

    try std.testing.expectEqual(body.randao_reveal.len, 96);
}

test "test BlobSidecar" {
    const sidecar = BlobSidecar{
        .index = 3,
        .blob = undefined,
        .kzg_commitment = undefined,
        .kzg_proof = undefined,
        .signed_block_header = undefined,
        .kzg_commitment_inclusion_proof = undefined,
    };

    try std.testing.expectEqual(sidecar.index, 3);
}

test "test BlobIdentifier" {
    const identifier = BlobIdentifier{
        .block_root = undefined,
        .index = undefined,
    };

    try std.testing.expectEqual(identifier.block_root.len, 32);
}
