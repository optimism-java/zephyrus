const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const bls = @import("../../bls/bls.zig");

const BLSError = error{
    InvalidPublicKey,
    EmptyPubkeysList,
};

/// Aggregates multiple BLS public keys into a single aggregate key
/// Params:
///   pubkeys: Slice of BLS public keys to aggregate
///   agg_pk: Pointer to store the resulting aggregate public key
/// Returns: Error if any key is invalid or input is empty
pub fn ethAggregatePubkeys(pub_keys: []const primitives.BLSPubkey, agg_pk_bytes: *[]u8) BLSError![]u8 {
    if (pub_keys.len == 0) return BLSError.EmptyPubkeysList;

    var processed: usize = 0;
    defer std.log.debug("Processed {} keys", .{processed});

    var agg_pk: bls.PublicKey = undefined;
    for (pub_keys) |pk_bytes| {
        var pk: bls.PublicKey = undefined;
        const res = pk.deserialize(&pk_bytes);
        if (!res) {
            return BLSError.InvalidPublicKey;
        }
        agg_pk.add(&pk);
        processed += 1;
    }

    return agg_pk.serialize(agg_pk_bytes);
}

test "test ethAggregatePubkeys" {
    const a = bls.init();
    try std.testing.expect(a);
    var sk: bls.SecretKey = undefined;
    var pk: bls.PublicKey = undefined;
    sk.setByCSPRNG();
    var buf128: [32]u8 = undefined;
    var buf: []u8 = &buf128;

    _ = sk.serialize(&buf);
    sk.getPublicKey(&pk);
    var buf2: primitives.BLSPubkey = undefined;
    var buf22: []u8 = &buf2;
    _ = pk.serialize(&buf22);

    const pubkeys = [_]primitives.BLSPubkey{ buf2, buf2, buf2 };
    var agg_pk: primitives.BLSPubkey = undefined;
    var agg_pk_bytes: []u8 = &agg_pk;
    _ = try ethAggregatePubkeys(pubkeys[0..], &agg_pk_bytes);

    try std.testing.expect(agg_pk_bytes.len == 48);
}
