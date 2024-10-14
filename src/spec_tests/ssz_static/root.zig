const std = @import("std");
const testing = std.testing;
const ssz = @import("../../ssz/ssz.zig");
const types = @import("../../consensus/types.zig");
const snappy = @import("../../snappy/snappy.zig");

test "hash tree root" {
    const fork = types.Fork{
        .previous_version = [4]u8{ 0x75, 0xeb, 0x7f, 0x25 },
        .current_version = [4]u8{ 0x10, 0xd4, 0xe2, 0x7f },
        .epoch = 8876772290899440384,
    };
    var out: [32]u8 = [_]u8{0} ** 32;
    try ssz.hashTreeRoot(fork, &out, testing.allocator);
    const expect: [32]u8 = [_]u8{ 0x98, 0x2a, 0x69, 0x96, 0xc9, 0x2f, 0x86, 0xf6, 0x37, 0x68, 0x3c, 0x72, 0xd9, 0x09, 0xc7, 0xa8, 0x68, 0x11, 0x0e, 0x3b, 0x05, 0xf7, 0xb4, 0x48, 0x44, 0xbc, 0x53, 0x96, 0x0d, 0x89, 0x56, 0xf5 };
    try std.testing.expect(std.mem.eql(u8, out[0..], expect[0..]));
    const file_path = "serialized.ssz_snappy";
    const file_contents = try std.fs.cwd().readFileAlloc(testing.allocator, file_path, std.math.maxInt(usize));
    defer testing.allocator.free(file_contents);
    // std.debug.print("Hex: {any}\n", .{std.fmt.fmtSliceHexLower(file_contents)});

    const decoded_data = try snappy.decode(testing.allocator, file_contents);
    defer testing.allocator.free(decoded_data);

    const encode = try ssz.encodeSSZ(testing.allocator, fork);
    defer testing.allocator.free(encode);

    try std.testing.expect(std.mem.eql(u8, encode, decoded_data));
}
