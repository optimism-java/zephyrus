//! The code bellow is essentially a combination of https://github.com/Raiden1411/zabi and https://github.com/gballet/ssz.zig
//! to the most recent version of zig with a couple of stylistic changes and support for
//! other zig types.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const sha256 = std.crypto.hash.sha2.Sha256;
const types = @import("../consensus/types.zig");

/// Set of possible errors while performing ssz decoding.
pub const SSZDecodeErrors = Allocator.Error || error{ InvalidEnumType, IndexOutOfBounds };

/// Performs ssz decoding according to the [specification](https://ethereum.org/developers/docs/data-structures-and-encoding/ssz).
pub fn decodeSSZ(comptime T: type, serialized: []const u8) SSZDecodeErrors!T {
    const info = @typeInfo(T);

    switch (info) {
        .bool => return serialized[0] != 0,
        .int => |int_info| return std.mem.readInt(T, serialized[0..@divExact(int_info.bits, 8)], .little),
        .optional => |opt_info| {
            const index = serialized[0];

            if (index != 0) {
                const result: opt_info.child = try decodeSSZ(opt_info.child, serialized[1..]);
                return result;
            } else return null;
        },
        .@"enum" => {
            const to_enum = std.meta.stringToEnum(T, serialized[0..]) orelse return error.InvalidEnumType;

            return to_enum;
        },
        .array => |arr_info| {
            if (arr_info.child == u8) {
                if (serialized.len >= arr_info.len) {
                    return serialized[0..arr_info.len].*;
                } else {
                    return error.IndexOutOfBounds;
                }
            }

            var result: T = undefined;

            if (arr_info.child == bool) {
                for (serialized, 0..) |byte, bindex| {
                    var index: u8 = 0;
                    var bit = byte;
                    while (bindex * 8 + index < arr_info.len and index < 8) : (index += 1) {
                        result[bindex * 8 + index] = bit & 1 == 1;
                        bit >>= 1;
                    }
                }

                return result;
            }

            if (isStaticType(arr_info.child)) {
                comptime var index = 0;
                const size = @sizeOf(arr_info.child);

                inline while (index < arr_info.len) : (index += 1) {
                    result[index] = try decodeSSZ(arr_info.child, serialized[index * size .. (index + 1) * size]);
                }

                return result;
            }

            const size = std.mem.readInt(u32, serialized[0..4], .little) / @sizeOf(u32);
            const indices = std.mem.bytesAsSlice(u32, serialized[0 .. size * 4]);

            var index: usize = 0;
            while (index < size) : (index += 1) {
                const final = if (index < size - 1) indices[index + 1] else serialized.len;
                const start = indices[index];

                if (start >= serialized.len or final > serialized.len)
                    return error.IndexOutOfBounds;

                result[index] = try decodeSSZ(arr_info.child, serialized[start..final]);
            }

            return result;
        },
        .vector => |vec_info| {
            var result: T = undefined;

            if (vec_info.child == bool) {
                for (serialized, 0..) |byte, bindex| {
                    var index: u8 = 0;
                    var bit = byte;
                    while (bindex * 8 + index < vec_info.len and index < 8) : (index += 1) {
                        result[bindex * 8 + index] = bit & 1 == 1;
                        bit >>= 1;
                    }
                }

                return result;
            }

            comptime var index = 0;
            const size = @sizeOf(vec_info.child);

            inline while (index < vec_info.len) : (index += 1) {
                result[index] = try decodeSSZ(vec_info.child, serialized[index * size .. (index + 1) * size]);
            }

            return result;
        },
        .pointer => return serialized[0..],
        .@"union" => |union_info| {
            const union_index = try decodeSSZ(u8, serialized);

            inline for (union_info.fields, 0..) |field, i| {
                if (union_index == i) {
                    return @unionInit(T, field.name, try decodeSSZ(field.type, serialized[1..]));
                }
            }
        },
        .@"struct" => |struct_info| {
            comptime var num_fields = 0;
            inline for (struct_info.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .bool, .int, .array => continue,
                    .@"struct" => {
                        if (isStaticType(field.type)) {
                            continue;
                        } else {
                            num_fields += 1;
                        }
                    },
                    else => num_fields += 1,
                }
            }
            var indices: [num_fields]u32 = undefined;
            var result: T = undefined;

            comptime var index = 0;
            comptime var field_index = 0;
            inline for (struct_info.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .bool, .int, .array => {
                        @field(result, field.name) = try decodeSSZ(field.type, serialized[index .. index + @sizeOf(field.type)]);
                        index += @sizeOf(field.type);
                    },
                    .@"struct" => {
                        if (isStaticType(field.type)) {
                            @field(result, field.name) = try decodeSSZ(field.type, serialized[index .. index + @sizeOf(field.type)]);
                            index += @sizeOf(field.type);
                        }
                    },
                    else => {
                        indices[field_index] = try decodeSSZ(u32, serialized[index .. index + 4]);
                        index += 4;
                        field_index += 1;
                    },
                }
            }

            comptime var final_index = 0;
            inline for (struct_info.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .bool, .int, .array => continue,
                    .@"struct" => {
                        if (isStaticType(field.type)) {
                            continue;
                        }
                    },
                    else => {
                        const final = if (final_index == indices.len - 1) serialized.len else indices[final_index + 1];
                        @field(result, field.name) = try decodeSSZ(field.type, serialized[indices[final_index]..final]);
                        final_index += 1;
                    },
                }
            }

            return result;
        },
        else => @compileError("Unsupported type " ++ @typeName(T)),
    }

    // it should never be reached
    unreachable;
}

/// Performs ssz encoding according to the [specification](https://ethereum.org/developers/docs/data-structures-and-encoding/ssz).
/// Almost all zig types are supported.
///
/// Caller owns the memory
pub fn encodeSSZ(allocator: Allocator, value: anytype) Allocator.Error![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    try encodeItem(value, &list);

    return try list.toOwnedSlice();
}

fn encodeItem(value: anytype, list: *std.ArrayList(u8)) Allocator.Error!void {
    const info = @typeInfo(@TypeOf(value));
    var writer = list.writer();

    switch (info) {
        .bool => try writer.writeInt(u8, @intFromBool(value), .little),
        .int => |int_info| {
            switch (int_info.bits) {
                8, 16, 32, 64, 128, 256 => try writer.writeInt(@TypeOf(value), value, .little),
                else => @compileError(std.fmt.comptimePrint("Unsupported {d} bits for ssz encoding", .{int_info.bits})),
            }
        },
        .comptime_int => {
            const size = comptime computeSize(@intCast(value)) * 8;
            switch (size) {
                8, 16, 32, 64, 128, 256 => try writer.writeInt(@Type(.{ .Int = .{ .signedness = .unsigned, .bits = size } }), value, .little),
                else => @compileError(std.fmt.comptimePrint("Unsupported {d} bits for ssz encoding", .{size})),
            }
        },
        .null => return,
        .optional => {
            if (value) |val| {
                try writer.writeInt(u8, 1, .little);
                return try encodeItem(val, list);
            } else try writer.writeInt(u8, 0, .little);
        },
        .@"union" => |union_info| {
            if (union_info.tag_type == null)
                @compileError("Untagged unions are not supported");

            inline for (union_info.fields, 0..) |field, i| {
                if (@intFromEnum(value) == i) {
                    try writer.writeInt(u8, i, .little);
                    return try encodeItem(@field(value, field.name), list);
                }
            }
        },
        .pointer => |ptr_info| {
            switch (ptr_info.size) {
                .One => return try encodeItem(value.*, list),
                .Slice => {
                    if (ptr_info.child == u8) {
                        try writer.writeAll(value);
                        return;
                    }

                    for (value) |val| {
                        try encodeItem(val, list);
                    }
                },
                else => @compileError("Unsupported pointer type " ++ @typeName(@TypeOf(value))),
            }
        },
        .vector => |vec_info| {
            if (vec_info.child == bool) {
                var as_byte: u8 = 0;
                for (value, 0..) |val, i| {
                    if (val) {
                        as_byte |= @as(u8, 1) << @as(u3, @truncate(i));
                    }

                    if (i % 8 == 7) {
                        try writer.writeByte(as_byte);
                        as_byte = 0;
                    }
                }

                if (as_byte % 8 != 0)
                    try writer.writeByte(as_byte);

                return;
            }

            for (0..vec_info.len) |i| {
                try encodeItem(value[i], list);
            }
        },
        .@"enum", .enum_literal => try writer.writeAll(@tagName(value)),
        .error_set => try writer.writeAll(@errorName(value)),
        .array => |arr_info| {
            if (arr_info.child == u8) {
                try writer.writeAll(&value);
                return;
            }

            if (arr_info.child == bool) {
                var as_byte: u8 = 0;
                for (value, 0..) |val, i| {
                    if (val) {
                        as_byte |= @as(u8, 1) << @as(u3, @truncate(i));
                    }

                    if (i % 8 == 7) {
                        try writer.writeByte(as_byte);
                        as_byte = 0;
                    }
                }

                if (as_byte % 8 != 0)
                    try writer.writeByte(as_byte);

                return;
            }

            if (isStaticType(arr_info.child)) {
                for (value) |val| {
                    try encodeItem(val, list);
                }
                return;
            }

            var offset_start = list.items.len;

            for (value) |_| {
                try writer.writeInt(u32, 0, .little);
            }

            for (value) |val| {
                std.mem.writeInt(u32, list.items[offset_start .. offset_start + 4][0..4], @as(u32, @truncate(list.items.len)), .little);
                try encodeItem(val, list);
                offset_start += 4;
            }
        },
        .@"struct" => |struct_info| {
            comptime var start: usize = 0;
            inline for (struct_info.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .int, .bool, .array => start += @sizeOf(field.type),
                    .@"struct" => {
                        if (isStaticType(field.type)) {
                            start += @sizeOf(field.type);
                        }
                    },
                    else => start += 4,
                }
            }

            var accumulate: usize = start;
            inline for (struct_info.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .int, .bool, .array => try encodeItem(@field(value, field.name), list),
                    .@"struct" => {
                        if (isStaticType(field.type)) {
                            try encodeItem(@field(value, field.name), list);
                        }
                    },
                    else => {
                        try encodeItem(@as(u32, @truncate(accumulate)), list);
                        accumulate += sizeOfValue(@field(value, field.name));
                    },
                }
            }

            if (accumulate > start) {
                inline for (struct_info.fields) |field| {
                    switch (@typeInfo(field.type)) {
                        .bool, .int => continue,
                        else => try encodeItem(@field(value, field.name), list),
                    }
                }
            }
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(value))),
    }
}

// Helpers
fn sizeOfValue(value: anytype) usize {
    const info = @typeInfo(@TypeOf(value));

    switch (info) {
        .array => return value.len,
        .pointer => switch (info.pointer.size) {
            .Slice => return value.len,
            else => return sizeOfValue(value.*),
        },
        .optional => return if (value == null)
            @intCast(1)
        else
            1 + sizeOfValue(value.?),
        .null => return @intCast(0),
        .@"struct" => |struct_info| {
            comptime var start: usize = 0;
            inline for (struct_info.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .int, .bool, .array => start += @sizeOf(field.type),
                    .@"struct" => {
                        start += sizeOfValue(field.type);
                    },
                    else => {},
                }
            }
            return start;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(value))),
    }
    // It should never reach this
    unreachable;
}

/// Checks if a given type is static
pub inline fn isStaticType(comptime T: type) bool {
    const info = @typeInfo(T);

    switch (info) {
        .bool, .int, .null => return true,
        .array => return true,
        .@"struct" => inline for (info.@"struct".fields) |field| {
            if (!isStaticType(field.type)) {
                return false;
            }
            return true;
        },
        .pointer => switch (info.pointer.size) {
            .Many, .Slice, .C => return false,
            .One => return isStaticType(info.Pointer.child),
        },
        else => @compileError("Unsupported type " ++ @typeName(T)),
    }
    // It should never reach this
    unreachable;
}

/// Computes the size of a given int
pub inline fn computeSize(int: u256) u8 {
    inline for (1..32) |i| {
        if (int < (1 << (8 * i))) {
            return i;
        }
    }

    return 32;
}

test "Bool" {
    {
        const encoded = try encodeSSZ(testing.allocator, true);
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{0x01};

        try testing.expectEqualSlices(u8, slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, false);
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{0x00};

        try testing.expectEqualSlices(u8, slice, encoded);
    }
}

test "Int" {
    {
        const encoded = try encodeSSZ(testing.allocator, @as(u8, 69));
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{0x45};

        try testing.expectEqualSlices(u8, slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, @as(u16, 69));
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{ 0x45, 0x00 };

        try testing.expectEqualSlices(u8, slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, @as(u32, 69));
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{ 0x45, 0x00, 0x00, 0x00 };

        try testing.expectEqualSlices(u8, slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, @as(i32, -69));
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{ 0xBB, 0xFF, 0xFF, 0xFF };

        try testing.expectEqualSlices(u8, slice, encoded);
    }
}

test "Arrays" {
    {
        const encoded = try encodeSSZ(testing.allocator, [_]bool{ true, false, true, true, false, false, false });
        defer testing.allocator.free(encoded);

        const slice = [_]u8{0b00001101};

        try testing.expectEqualSlices(u8, &slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, [_]bool{ true, false, true, true, false, false, false, true });
        defer testing.allocator.free(encoded);

        const slice = [_]u8{0b10001101};

        try testing.expectEqualSlices(u8, &slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, [_]bool{ true, false, true, true, false, false, false, true, false, true, false, true });
        defer testing.allocator.free(encoded);

        const slice = [_]u8{ 0x8D, 0x0A };

        try testing.expectEqualSlices(u8, &slice, encoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, [_]u16{ 0xABCD, 0xEF01 });
        defer testing.allocator.free(encoded);

        const slice = &[_]u8{ 0xCD, 0xAB, 0x01, 0xEF };

        try testing.expectEqualSlices(u8, slice, encoded);
    }
}

test "Struct" {
    {
        const data = .{
            .uint8 = @as(u8, 1),
            .uint32 = @as(u32, 3),
            .boolean = true,
        };
        const encoded = try encodeSSZ(testing.allocator, data);
        defer testing.allocator.free(encoded);

        const slice = [_]u8{ 1, 3, 0, 0, 0, 1 };
        try testing.expectEqualSlices(u8, &slice, encoded);
    }
    {
        const data = .{
            .name = "James",
            .age = @as(u8, 32),
            .company = "DEV Inc.",
        };
        const encoded = try encodeSSZ(testing.allocator, data);
        defer testing.allocator.free(encoded);

        const slice = [_]u8{ 9, 0, 0, 0, 32, 14, 0, 0, 0, 74, 97, 109, 101, 115, 68, 69, 86, 32, 73, 110, 99, 46 };
        try testing.expectEqualSlices(u8, &slice, encoded);
    }
}

test "Decoded Bool" {
    {
        const decoded = try decodeSSZ(bool, &[_]u8{0x01});

        try testing.expect(decoded);
    }
    {
        const decoded = try decodeSSZ(bool, &[_]u8{0x00});

        try testing.expect(!decoded);
    }
}

test "Decoded Int" {
    {
        const decoded = try decodeSSZ(u8, &[_]u8{0x45});
        try testing.expectEqual(69, decoded);
    }
    {
        const decoded = try decodeSSZ(u16, &[_]u8{ 0x45, 0x00 });
        try testing.expectEqual(69, decoded);
    }
    {
        const decoded = try decodeSSZ(u32, &[_]u8{ 0x45, 0x00, 0x00, 0x00 });
        try testing.expectEqual(69, decoded);
    }
    {
        const decoded = try decodeSSZ(i32, &[_]u8{ 0xBB, 0xFF, 0xFF, 0xFF });
        try testing.expectEqual(-69, decoded);
    }
}

test "Decoded String" {
    {
        const slice: []const u8 = "FOO";

        const decoded = try decodeSSZ([]const u8, slice);

        try testing.expectEqualStrings(slice, decoded);
    }
    {
        const slice = "FOO";

        const decoded = try decodeSSZ([]const u8, slice);

        try testing.expectEqualStrings(slice, decoded);
    }
    {
        const Enum = enum { foo, bar };

        const encode = try encodeSSZ(testing.allocator, Enum.foo);
        defer testing.allocator.free(encode);

        const decoded = try decodeSSZ(Enum, encode);

        try testing.expectEqual(Enum.foo, decoded);
    }
}

test "Decoded Array" {
    {
        const encoded = [_]bool{ true, false, true, true, false, false, false, true, false, true, false, true };

        const slice = [_]u8{ 0x8D, 0x0A };

        const decoded = try decodeSSZ([12]bool, &slice);

        try testing.expectEqualSlices(bool, &encoded, &decoded);
    }
    {
        const encoded = [_]u16{ 0xABCD, 0xEF01 };

        const slice = &[_]u8{ 0xCD, 0xAB, 0x01, 0xEF };

        const decoded = try decodeSSZ([2]u16, slice);

        try testing.expectEqualSlices(u16, &encoded, &decoded);
    }
    {
        const encoded = try encodeSSZ(testing.allocator, pastries);
        defer testing.allocator.free(encoded);
        const decoded = try decodeSSZ([2]Pastry, encoded);

        try testing.expectEqualDeep(pastries, decoded);
    }
}

const Pastry = struct {
    name: []const u8,
    weight: u16,
};

const pastries = [_]Pastry{
    Pastry{
        .name = "croissant",
        .weight = 20,
    },
    Pastry{
        .name = "Herrentorte",
        .weight = 500,
    },
};

test "Decode Struct" {
    const pastry = Pastry{
        .name = "croissant",
        .weight = 20,
    };

    const encoded = try encodeSSZ(testing.allocator, pastry);
    defer testing.allocator.free(encoded);

    const decoded = try decodeSSZ(Pastry, encoded);

    try testing.expectEqualDeep(pastry, decoded);
}

test "Decode Fork" {
    const fork = types.Fork{
        .current_version = [4]u8{ 1, 2, 3, 4 },
        .previous_version = [4]u8{ 1, 2, 3, 4 },
        .epoch = 10,
    };
    const encoded = try encodeSSZ(testing.allocator, fork);
    defer testing.allocator.free(encoded);
    const decoded = try decodeSSZ(types.Fork, encoded);
    try testing.expectEqualDeep(fork, decoded);
}

test "Decode Union" {
    const Union = union(enum) {
        foo: u32,
        bar: bool,
    };

    {
        const un = Union{ .foo = 69 };
        const encoded = try encodeSSZ(testing.allocator, un);
        defer testing.allocator.free(encoded);

        const decoded = try decodeSSZ(Union, encoded);

        try testing.expectEqualDeep(un, decoded);
    }
    {
        const un = Union{ .bar = true };
        const encoded = try encodeSSZ(testing.allocator, un);
        defer testing.allocator.free(encoded);

        const decoded = try decodeSSZ(Union, encoded);

        try testing.expectEqualDeep(un, decoded);
    }
}

test "Decode Optional" {
    const foo: ?u32 = 69;

    const encoded = try encodeSSZ(testing.allocator, foo);
    defer testing.allocator.free(encoded);

    const decoded = try decodeSSZ(?u32, encoded);

    try testing.expectEqualDeep(foo, decoded);
}

test "Decode Vector" {
    {
        const encoded: @Vector(12, bool) = .{ true, false, true, true, false, false, false, true, false, true, false, true };
        const slice = [_]u8{ 0x8D, 0x0A };

        const decoded = try decodeSSZ(@Vector(12, bool), &slice);

        try testing.expectEqualDeep(encoded, decoded);
    }
    {
        const encoded: @Vector(2, u16) = .{ 0xABCD, 0xEF01 };
        const slice = &[_]u8{ 0xCD, 0xAB, 0x01, 0xEF };

        const decoded = try decodeSSZ(@Vector(2, u16), slice);

        try testing.expectEqualDeep(encoded, decoded);
    }
}

/// Number of bytes per chunk.
const BYTES_PER_CHUNK = 32;

/// Number of bytes per serialized length offset.
const BYTES_PER_LENGTH_OFFSET = 4;

fn mixInLength(root: [32]u8, length: [32]u8, out: *[32]u8) void {
    var hasher = sha256.init(sha256.Options{});
    hasher.update(root[0..]);
    hasher.update(length[0..]);
    hasher.final(out);
}

test "mixInLength" {
    var root: [32]u8 = undefined;
    var length: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    var mixin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(root[0..], "2279cf111c15f2d594e7a0055e8735e7409e56ed4250735d6d2f2b0d1bcf8297");
    _ = try std.fmt.hexToBytes(length[0..], "deadbeef00000000000000000000000000000000000000000000000000000000");
    _ = try std.fmt.hexToBytes(expected[0..], "0b665dda6e4c269730bc4bbe3e990a69d37fa82892bac5fe055ca4f02a98c900");
    mixInLength(root, length, &mixin);

    try std.testing.expect(std.mem.eql(u8, mixin[0..], expected[0..]));
}

fn mixInSelector(root: [32]u8, comptime selector: usize, out: *[32]u8) void {
    var hasher = sha256.init(sha256.Options{});
    hasher.update(root[0..]);
    var tmp = [_]u8{0} ** 32;
    std.mem.writeInt(@TypeOf(selector), tmp[0..@sizeOf(@TypeOf(selector))], selector, .little);
    hasher.update(tmp[0..]);
    hasher.final(out);
}

test "mixInSelector" {
    var root: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    var mixin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(root[0..], "2279cf111c15f2d594e7a0055e8735e7409e56ed4250735d6d2f2b0d1bcf8297");
    _ = try std.fmt.hexToBytes(expected[0..], "c483cb731afcfe9f2c596698eaca1c4e0dcb4a1136297adef74c31c268966eb5");
    mixInSelector(root, 25, &mixin);

    try std.testing.expect(std.mem.eql(u8, mixin[0..], expected[0..]));
}

pub fn chunkCount(comptime T: type) usize {
    const info = @typeInfo(T);
    switch (info) {
        .int, .bool => return 1,
        .pointer => return chunkCount(info.pointer.child),
        .array => switch (@typeInfo(info.array.child)) {
            // Bitvector[N]
            .bool => return (info.array.len + 255) / 256,
            // Vector[B,N]
            .int => return (info.Array.len * @sizeOf(info.Array.child) + 31) / 32,
            // Vector[C,N]
            else => return info.array.len,
        },
        .@"struct" => return info.@"struct".fields.len,
        else => return error.NotSupported,
    }
}

const chunk = [BYTES_PER_CHUNK]u8;
const zero_chunk: chunk = [_]u8{0} ** BYTES_PER_CHUNK;

fn pack(value: anytype, l: *ArrayList(u8)) ![]chunk {
    const encoded = try encodeSSZ(l.allocator, value);
    try l.appendSlice(encoded);
    l.allocator.free(encoded);

    const padding_size = (BYTES_PER_CHUNK - l.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
    try l.appendSlice(zero_chunk[0..padding_size]);

    return std.mem.bytesAsSlice(chunk, l.items);
}

test "pack u32" {
    var expected: [32]u8 = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const data: u32 = 0xdeadbeef;
    const out = try pack(data, &list);

    _ = try std.fmt.hexToBytes(expected[0..], "efbeadde00000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..]));
}

test "pack bool" {
    var expected: [32]u8 = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const out = try pack(true, &list);

    _ = try std.fmt.hexToBytes(expected[0..], "0100000000000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..]));
}

test "pack string" {
    var expected: [128]u8 = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const data: []const u8 = "a" ** 100;
    const out = try pack(data, &list);

    _ = try std.fmt.hexToBytes(expected[0..], "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(expected.len == out.len * out[0].len);
    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..32]));
    try std.testing.expect(std.mem.eql(u8, out[1][0..], expected[32..64]));
    try std.testing.expect(std.mem.eql(u8, out[2][0..], expected[64..96]));
    try std.testing.expect(std.mem.eql(u8, out[3][0..], expected[96..]));
}

fn nextPowOfTwo(len: usize) !usize {
    if (len == 0) {
        return @as(usize, 0);
    }

    // check that the msb isn't set and
    // return an error if it is, as it
    // would overflow.
    if (@clz(len) == 0) {
        return error.OverflowsUSize;
    }

    const n = std.math.log2(std.math.shl(usize, len, 1) - 1);
    return std.math.powi(usize, 2, n);
}

test "next power of 2" {
    var out = try nextPowOfTwo(0b1);
    try std.testing.expect(out == 1);
    out = try nextPowOfTwo(0b10);
    try std.testing.expect(out == 2);
    out = try nextPowOfTwo(0b11);
    try std.testing.expect(out == 4);

    // special cases
    out = try nextPowOfTwo(0);
    try std.testing.expect(out == 0);
    try std.testing.expectError(error.OverflowsUSize, nextPowOfTwo(std.math.maxInt(usize)));
}

const hashes_of_zero = @import("./zeros.zig").hashes_of_zero;

pub fn merkleize(chunks: []chunk, limit: ?usize, out: *[32]u8) anyerror!void {
    if (limit != null and chunks.len > limit.?) {
        return error.ChunkSizeExceedsLimit;
    }

    const size = try nextPowOfTwo(limit orelse chunks.len);

    // Perform the merkleization.
    switch (size) {
        0 => std.mem.copyForwards(u8, out, &zero_chunk),
        1 => std.mem.copyForwards(u8, out, chunks[0][0..]),
        else => {
            var hasher = sha256.init(sha256.Options{});
            var buf: [32]u8 = undefined;
            const split = if (size / 2 < chunks.len) size / 2 else chunks.len;
            try merkleize(chunks[0..split], size / 2, &buf);
            hasher.update(buf[0..]);

            if (size / 2 < chunks.len) {
                try merkleize(chunks[size / 2 ..], size / 2, &buf);
                hasher.update(buf[0..]);
            } else {
                const power = std.math.log2(size);
                hasher.update(hashes_of_zero[power - 1][0..]);
            }
            hasher.final(out);
        },
    }
}

test "merkleize a string" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const data: []const u8 = "a" ** 100;
    const chunks = try pack(data, &list);
    var out: [32]u8 = undefined;
    try merkleize(chunks, null, &out);
    // Build the expected tree
    const leaf1 = [_]u8{0x61} ** 32; // "0xaaaaa....aa" 32 times
    var leaf2: [32]u8 = [_]u8{0x61} ** 4 ++ [_]u8{0} ** 28;
    var root: [32]u8 = undefined;
    var internal_left: [32]u8 = undefined;
    var internal_right: [32]u8 = undefined;
    var hasher = sha256.init(sha256.Options{});
    hasher.update(leaf1[0..]);
    hasher.update(leaf1[0..]);
    hasher.final(&internal_left);
    hasher = sha256.init(sha256.Options{});
    hasher.update(leaf1[0..]);
    hasher.update(leaf2[0..]);
    hasher.final(&internal_right);
    hasher = sha256.init(sha256.Options{});
    hasher.update(internal_left[0..]);
    hasher.update(internal_right[0..]);
    hasher.final(&root);

    try std.testing.expect(std.mem.eql(u8, out[0..], root[0..]));
}

test "merkleize a boolean" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    var chunks = try pack(false, &list);
    var expected = [_]u8{0} ** BYTES_PER_CHUNK;
    var out: [BYTES_PER_CHUNK]u8 = undefined;
    try merkleize(chunks, null, &out);

    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();

    chunks = try pack(true, &list2);
    expected[0] = 1;
    try merkleize(chunks, null, &out);
    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));
}

test "merkleize a bytes16 vector with one element" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const chunks = try pack([_]u8{0xaa} ** 16, &list);
    var expected: [32]u8 = [_]u8{0xaa} ** 16 ++ [_]u8{0x00} ** 16;
    var out: [32]u8 = undefined;
    try merkleize(chunks, null, &out);
    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));
}

fn packBits(bits: []const bool, l: ArrayList(u8)) ![]chunk {
    var byte: u8 = 0;
    for (bits, 0..) |bit, bitIdx| {
        if (bit) {
            byte |= @as(u8, 1) << @as(u3, @truncate(7 - bitIdx % 8));
        }
        if (bitIdx % 8 == 7 or bitIdx == bits.len - 1) {
            try l.append(byte);
            byte = 0;
        }
    }
    // pad the last chunk with 0s
    const padding_size = (BYTES_PER_CHUNK - l.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
    _ = try l.writer().write(zero_chunk[0..padding_size]);

    return std.mem.bytesAsSlice(chunk, l.items);
}

pub fn hashTreeRoot(value: anytype, out: *[32]u8, allocator: Allocator) !void {
    const type_info = @typeInfo(@TypeOf(value));
    switch (type_info) {
        .int, .bool => {
            var list = ArrayList(u8).init(allocator);
            defer list.deinit();
            const chunks = try pack(value, &list);
            try merkleize(chunks, null, out);
        },
        .array => {
            switch (@typeInfo(type_info.array.child)) {
                .int => {
                    var list = ArrayList(u8).init(allocator);
                    defer list.deinit();
                    const chunks = try pack(value, &list);
                    try merkleize(chunks, null, out);
                },
                .bool => {
                    var list = ArrayList(u8).init(allocator);
                    defer list.deinit();
                    const chunks = try packBits(value, list);
                    try merkleize(chunks, null, out);
                },
                .array => {
                    var chunks = ArrayList(chunk).init(allocator);
                    defer chunks.deinit();
                    var tmp: chunk = undefined;
                    for (value) |item| {
                        try hashTreeRoot(item, &tmp, allocator);
                        try chunks.append(tmp);
                    }
                    try merkleize(chunks.items, null, out);
                },
                else => return error.NotSupported,
            }
        },
        .pointer => {
            switch (type_info.pointer.size) {
                .One => try hashTreeRoot(value.*, out, allocator),
                .Slice => {
                    switch (@typeInfo(type_info.pointer.child)) {
                        .int => {
                            var list = ArrayList(u8).init(allocator);
                            defer list.deinit();
                            const chunks = try pack(value, &list);
                            try merkleize(chunks, null, out);
                        },
                        else => return error.UnSupportedPointerType,
                    }
                },
                else => return error.UnSupportedPointerType,
            }
        },
        .@"struct" => {
            var chunks = ArrayList(chunk).init(allocator);
            defer chunks.deinit();
            var tmp: chunk = undefined;
            inline for (type_info.@"struct".fields) |f| {
                try hashTreeRoot(@field(value, f.name), &tmp, allocator);
                try chunks.append(tmp);
            }
            try merkleize(chunks.items, null, out);
        },
        .optional => if (value != null) {
            var tmp: chunk = undefined;
            try hashTreeRoot(value.?, &tmp, allocator);
            mixInSelector(tmp, 1, out);
        } else {
            mixInSelector(zero_chunk, 0, out);
        },
        .@"union" => {
            if (type_info.@"union".tag_type == null) {
                return error.UnionIsNotTagged;
            }
            inline for (type_info.@"union".fields, 0..) |f, index| {
                if (@intFromEnum(value) == index) {
                    var tmp: chunk = undefined;
                    try hashTreeRoot(@field(value, f.name), &tmp, allocator);
                    mixInSelector(tmp, index, out);
                }
            }
        },
        else => return error.NotSupported,
    }
}
