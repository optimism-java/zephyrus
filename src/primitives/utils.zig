const std = @import("std");
const constants = @import("constants.zig");
const testing = std.testing;

pub fn ceilLog2(x: usize) u64 {
    if (x < 1) {
        @panic("ceillog2 accepts only positive values");
    }
    return @as(u64, @bitSizeOf(u64) - @clz(x - 1));
}

pub fn floorLog2(x: usize) u64 {
    if (x < 1) {
        @panic("floorlog2 accepts only positive values");
    }
    return @as(u64, @bitSizeOf(u64) - @clz(x) - 1);
}

pub fn integerSquareroot(n: u64) u64 {
    if (n == std.math.maxInt(u64)) {
        return constants.UINT64_MAX_SQRT; // UINT64_MAX_SQRT
    }
    var x = n;
    var y = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

test "ceilLog2 with valid inputs" {
    try testing.expectEqual(@as(u64, 0), ceilLog2(1));
    try testing.expectEqual(@as(u64, 1), ceilLog2(2));
    try testing.expectEqual(@as(u64, 2), ceilLog2(3));
    try testing.expectEqual(@as(u64, 2), ceilLog2(4));
    try testing.expectEqual(@as(u64, 3), ceilLog2(5));
    try testing.expectEqual(@as(u64, 6), ceilLog2(63));
    try testing.expectEqual(@as(u64, 6), ceilLog2(64));
    try testing.expectEqual(@as(u64, 7), ceilLog2(65));
}

test "ceilLog2 with maximum u64 value" {
    try testing.expectEqual(@as(u64, 64), ceilLog2(std.math.maxInt(u64)));
}

// test "ceilLog2 panics with 0" {
//     testing.expectPanic(ceilLog2(0));
// }

test "floorLog2 with valid inputs" {
    try testing.expectEqual(@as(u64, 0), floorLog2(1));
    try testing.expectEqual(@as(u64, 1), floorLog2(2));
    try testing.expectEqual(@as(u64, 1), floorLog2(3));
    try testing.expectEqual(@as(u64, 2), floorLog2(4));
    try testing.expectEqual(@as(u64, 2), floorLog2(5));
    try testing.expectEqual(@as(u64, 5), floorLog2(63));
    try testing.expectEqual(@as(u64, 6), floorLog2(64));
    try testing.expectEqual(@as(u64, 6), floorLog2(65));
}

test "floorLog2 with maximum u64 value" {
    try testing.expectEqual(@as(u64, 63), floorLog2(std.math.maxInt(u64)));
}

// test "floorLog2 panics with 0" {
//     testing.expectPanic(floorLog2(0));
// }
