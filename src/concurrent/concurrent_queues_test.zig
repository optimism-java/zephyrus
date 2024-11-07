const std = @import("std");
const testing = std.testing;
const ConcurrentQueue = @import("concurrent_queues.zig").ConcurrentQueue;

test "ConcurrentQueue.push - basic push operation" {
    var queue = ConcurrentQueue(i32, .Spsc).init(testing.allocator, 4) catch unreachable;
    defer queue.deinit();

    try testing.expect(queue.push(1));
    try testing.expect(queue.push(2));
    try testing.expect(queue.push(3));
}

test "ConcurrentQueue.push - queue full" {
    var queue = ConcurrentQueue(i32, .Spsc).init(testing.allocator, 2) catch unreachable;
    defer queue.deinit();

    try testing.expect(queue.push(1));
    try testing.expect(queue.push(2));
    try testing.expect(!queue.push(3));
}

test "ConcurrentQueue.push - wrap around" {
    var queue = ConcurrentQueue(i32, .Spsc).init(testing.allocator, 4) catch unreachable;
    defer queue.deinit();

    try testing.expect(queue.push(1));
    try testing.expect(queue.push(2));
    _ = queue.pop();
    _ = queue.pop();
    try testing.expect(queue.push(3));
    try testing.expect(queue.push(4));
}

test "ConcurrentQueue.push - different types" {
    var queue = ConcurrentQueue(f32, .Spsc).init(testing.allocator, 2) catch unreachable;
    defer queue.deinit();

    try testing.expect(queue.push(1.5));
    try testing.expect(queue.push(2.5));
}
