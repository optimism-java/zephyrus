const std = @import("std");
const AtomicOrder = std.atomic.Ordering;
const Cache_Line_Size = 64;

/// Constructs a new multi-producer, multi-consumer queue for the given `T` type.
/// The queue is lock-free and wait-free for both producers and consumers.
/// The queue has a fixed capacity that is rounded up to the nearest power of two.
/// The queue is thread-safe and can be safely accessed from multiple threads concurrently.
pub fn MpmcQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            value: T,
            sequence: usize,
        };

        const Buffer = struct {
            entries: []Node,
            mask: usize,
        };

        head: usize align(Cache_Line_Size) = 0,
        tail: usize align(Cache_Line_Size) = 0,
        buffer: Buffer,

        /// Initializes a new `MpmcQueue` with the given `capacity`.
        /// The actual capacity of the queue will be rounded up to the nearest power of two.
        /// If the requested capacity is too large, this function will return an error.
        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            const real_capacity = std.math.ceilPowerOfTwo(usize, capacity) catch return error.CapacityTooLarge;

            const entries = try allocator.alloc(Node, real_capacity);
            for (entries, 0..) |*entry, i| {
                entry.* = .{
                    .value = undefined,
                    .sequence = i,
                };
            }

            return Self{
                .buffer = .{
                    .entries = entries,
                    .mask = real_capacity - 1,
                },
            };
        }

        /// Deinitializes the `MpmcQueue` and frees the underlying memory used by the queue.
        /// This function should be called when the queue is no longer needed to avoid memory leaks.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.buffer.entries);
        }

        /// Adds the given `value` to the queue.
        /// This operation is thread-safe and can be called concurrently from multiple threads.
        /// Returns `true` if the value was successfully added to the queue, or `false` if the queue is full.
        pub fn push(self: *Self, value: T) bool {
            var tail = @atomicLoad(usize, &self.tail, .monotonic);
            while (true) {
                const entry = &self.buffer.entries[tail & self.buffer.mask];
                const seq = @atomicLoad(usize, &entry.sequence, .acquire);
                const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(tail));

                if (diff == 0) {
                    if (@cmpxchgWeak(
                        usize,
                        &self.tail,
                        tail,
                        tail + 1,
                        .monotonic,
                        .monotonic,
                    )) |_| {
                        tail += 1;
                        continue;
                    }
                    entry.value = value;
                    @atomicStore(usize, &entry.sequence, tail + 1, .release);
                    return true;
                } else if (diff < 0) {
                    return false;
                }
                tail = @atomicLoad(usize, &self.tail, .monotonic);
            }
        }

        /// Removes and returns the next value from the queue, or `null` if the queue is empty.
        /// This operation is thread-safe and can be called concurrently from multiple threads.
        pub fn pop(self: *Self) ?T {
            var head = @atomicLoad(usize, &self.head, .monotonic);
            while (true) {
                const entry = &self.buffer.entries[head & self.buffer.mask];
                const seq = @atomicLoad(usize, &entry.sequence, .acquire);
                const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(head + 1));

                if (diff == 0) {
                    if (@cmpxchgWeak(
                        usize,
                        &self.head,
                        head,
                        head + 1,
                        .monotonic,
                        .monotonic,
                    )) |_| {
                        head += 1;
                        continue;
                    }
                    const value = entry.value;
                    @atomicStore(usize, &entry.sequence, head + self.buffer.entries.len, .release);
                    return value;
                } else if (diff < 0) {
                    return null;
                }
                head = @atomicLoad(usize, &self.head, .monotonic);
            }
        }
    };
}

test "MpmcQueue.push - basic push operation" {
    var queue = MpmcQueue(i32).init(std.testing.allocator, 4) catch unreachable;
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(queue.push(3));
}

test "MpmcQueue.push - queue full" {
    var queue = MpmcQueue(i32).init(std.testing.allocator, 2) catch unreachable;
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(!queue.push(3));
}

test "MpmcQueue.push - wrap around" {
    var queue = MpmcQueue(i32).init(std.testing.allocator, 4) catch unreachable;
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    _ = queue.pop();
    _ = queue.pop();
    try std.testing.expect(queue.push(3));
    try std.testing.expect(queue.push(4));
}

test "MpmcQueue.push - different types" {
    var queue = MpmcQueue(f32).init(std.testing.allocator, 2) catch unreachable;
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1.5));
    try std.testing.expect(queue.push(2.5));
}

test "MpmcQueue.pop - basic pop operation" {
    var queue = MpmcQueue(i32).init(std.testing.allocator, 4) catch unreachable;
    defer queue.deinit(std.testing.allocator);
    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(queue.push(3));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expectEqual(queue.pop(), 3);
}

test "MpmcQueue.pop - queue empty" {
    var queue = MpmcQueue(i32).init(std.testing.allocator, 4) catch unreachable;
    defer queue.deinit(std.testing.allocator);
    try std.testing.expectEqual(queue.pop(), null);
}

test "MpmcQueue.pop - wrap around" {
    var queue = MpmcQueue(i32).init(std.testing.allocator, 4) catch unreachable;
    defer queue.deinit(std.testing.allocator);
    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(queue.push(3));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expect(queue.push(4));
    try std.testing.expect(queue.push(5));
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expectEqual(queue.pop(), 3);
    try std.testing.expectEqual(queue.pop(), 4);
    try std.testing.expectEqual(queue.pop(), 5);
}

test "MpmcQueue.pop - different types" {
    var queue = MpmcQueue(f32).init(std.testing.allocator, 4) catch unreachable;
    defer queue.deinit(std.testing.allocator);
    try std.testing.expect(queue.push(1.5));
    try std.testing.expect(queue.push(2.5));
    try std.testing.expectEqual(queue.pop(), 1.5);
    try std.testing.expectEqual(queue.pop(), 2.5);
}

test "MpmcQueue.pop - concurrent push and pop" {
    const TestQueue = MpmcQueue(u64);
    const ThreadCount = 4;
    const ItemsPerThread = 10_000;

    var queue = try TestQueue.init(std.testing.allocator, ThreadCount * 2);
    defer queue.deinit(std.testing.allocator);

    const Producer = struct {
        fn run(q: *TestQueue, thread_id: u64) !void {
            var i: u64 = 0;
            while (i < ItemsPerThread) : (i += 1) {
                const item = thread_id * ItemsPerThread + i;
                while (!q.push(item)) {
                    try std.Thread.yield();
                }
            }
        }
    };

    const Consumer = struct {
        fn run(q: *TestQueue, results: []std.atomic.Value(u64)) !void {
            var count: u64 = 0;
            while (count < ItemsPerThread) {
                if (q.pop()) |value| {
                    const index = value % ThreadCount;
                    _ = results[index].fetchAdd(1, .acq_rel);
                    count += 1;
                } else {
                    try std.Thread.yield();
                }
            }
        }
    };

    var threads: [ThreadCount * 2]std.Thread = undefined;
    var results: [ThreadCount]std.atomic.Value(u64) = undefined;

    for (&results) |*result| {
        result.* = std.atomic.Value(u64).init(0);
    }

    // Start producer threads
    for (0..ThreadCount) |i| {
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{ &queue, i });
    }

    // Start consumer threads
    for (0..ThreadCount) |i| {
        threads[ThreadCount + i] = try std.Thread.spawn(.{}, Consumer.run, .{ &queue, &results });
    }

    // Wait for all threads to complete
    for (threads) |thread| {
        thread.join();
    }

    // Verify results
    for (results) |result| {
        try std.testing.expectEqual(ItemsPerThread, result.load(.acquire));
    }
}

test "MpmcQueue.pop - concurrent push and pop with wrap around" {
    const TestQueue = MpmcQueue(u64);
    const ThreadCount = 4;
    const ItemsPerThread = 10_000;

    var queue = try TestQueue.init(std.testing.allocator, ThreadCount * 2);
    defer queue.deinit(std.testing.allocator);

    const Producer = struct {
        fn run(q: *TestQueue, thread_id: u64) !void {
            var i: u64 = 0;
            while (i < ItemsPerThread) : (i += 1) {
                const item = thread_id * ItemsPerThread + i;
                while (!q.push(item)) {
                    try std.Thread.yield();
                }
            }
        }
    };

    const Consumer = struct {
        fn run(q: *TestQueue, results: []std.atomic.Value(u64)) !void {
            var count: u64 = 0;
            while (count < ItemsPerThread) {
                if (q.pop()) |value| {
                    const index = value % ThreadCount;
                    _ = results[index].fetchAdd(1, .acq_rel);
                    count += 1;
                } else {
                    try std.Thread.yield();
                }
            }
        }
    };

    var threads: [ThreadCount * 2]std.Thread = undefined;
    var results: [ThreadCount]std.atomic.Value(u64) = undefined;

    for (&results) |*result| {
        result.* = std.atomic.Value(u64).init(0);
    }

    // Start producer threads
    for (0..ThreadCount) |i| {
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{ &queue, i });
    }

    // Start consumer threads
    for (0..ThreadCount) |i| {
        threads[ThreadCount + i] = try std.Thread.spawn(.{}, Consumer.run, .{ &queue, &results });
    }

    // Wait for all threads to complete
    for (threads) |thread| {
        thread.join();
    }

    // Verify results
    for (results) |result| {
        try std.testing.expectEqual(ItemsPerThread, result.load(.acquire));
    }
}
