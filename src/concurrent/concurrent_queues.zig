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

/// A multi-producer, single-consumer (MPSC) queue implementation.
///
/// This queue is designed to be used in concurrent environments where multiple
/// producers can enqueue items, but only a single consumer dequeues them.
/// The queue uses atomic operations to ensure thread-safety and lock-free
/// access.
pub fn MpscQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            value: T,
            sequence: std.atomic.Value(usize),
        };

        const Buffer = struct {
            entries: []Node,
            mask: usize,
        };

        head: std.atomic.Value(usize) align(Cache_Line_Size),
        tail: usize align(Cache_Line_Size),
        buffer: Buffer,

        /// Initializes a new `MpscQueue` with the specified capacity.
        ///
        /// The capacity is rounded up to the nearest power of two to optimize the
        /// internal buffer. If the requested capacity is too large, an error is
        /// returned.
        ///
        /// The returned `MpscQueue` is ready to be used for concurrent enqueue and
        /// dequeue operations.
        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            const real_capacity = std.math.ceilPowerOfTwo(usize, capacity) catch return error.CapacityTooLarge;

            const entries = try allocator.alloc(Node, real_capacity);
            for (entries, 0..) |*entry, i| {
                entry.* = .{
                    .value = undefined,
                    .sequence = std.atomic.Value(usize).init(i),
                };
            }

            return Self{
                .head = std.atomic.Value(usize).init(0),
                .tail = 0,
                .buffer = .{
                    .entries = entries,
                    .mask = real_capacity - 1,
                },
            };
        }

        /// Attempts to push the given value onto the queue.
        ///
        /// This function uses a lock-free algorithm to enqueue the value. It will
        /// spin until it is able to successfully enqueue the value.
        ///
        /// Returns `true` if the value was successfully enqueued, `false` otherwise.
        pub fn push(self: *Self, value: T) bool {
            while (true) {
                const current_head = self.head.load(.monotonic);
                const entry = &self.buffer.entries[current_head & self.buffer.mask];
                const seq = entry.sequence.load(.acquire);
                const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(current_head));

                if (diff == 0) {
                    if (@cmpxchgWeak(
                        usize,
                        &self.head.raw,
                        current_head,
                        current_head + 1,
                        .monotonic,
                        .monotonic,
                    )) |_| {
                        continue;
                    }
                    entry.value = value;
                    entry.sequence.store(current_head + 1, .release);
                    return true;
                } else if (diff < 0) {
                    return false;
                }
            }
        }

        /// Attempts to dequeue a value from the queue.
        ///
        /// This function uses a lock-free algorithm to dequeue a value. It will spin until
        /// it is able to successfully dequeue a value or determine that the queue is empty.
        ///
        /// Returns the dequeued value if successful, `null` if the queue is empty.
        pub fn pop(self: *Self) ?T {
            const entry = &self.buffer.entries[self.tail & self.buffer.mask];
            const seq = entry.sequence.load(.acquire);
            const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(self.tail + 1));

            if (diff == 0) {
                const value = entry.value;
                entry.sequence.store(self.tail + self.buffer.entries.len, .release);
                self.tail += 1;
                return value;
            }
            return null;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.buffer.entries);
        }
    };
}

test "MpscQueue - single producer basic operations" {
    var queue = try MpscQueue(i32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expectEqual(queue.pop(), null);
}

test "MpscQueue - queue full" {
    var queue = try MpscQueue(i32).init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(!queue.push(3));
}

test "MpscQueue - multiple producers" {
    const ProducerCount = 4;
    const ItemsPerProducer = 10_000;

    var queue = try MpscQueue(u64).init(std.testing.allocator, ProducerCount * 2);
    defer queue.deinit(std.testing.allocator);

    const Producer = struct {
        fn run(q: *MpscQueue(u64), producer_id: u64) !void {
            var i: u64 = 0;
            while (i < ItemsPerProducer) : (i += 1) {
                const item = producer_id * ItemsPerProducer + i;
                while (!q.push(item)) {
                    try std.Thread.yield();
                }
            }
        }
    };

    var threads: [ProducerCount]std.Thread = undefined;
    var received = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer received.deinit();

    for (0..ProducerCount) |i| {
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{ &queue, i });
    }

    var total_received: usize = 0;
    while (total_received < ProducerCount * ItemsPerProducer) {
        if (queue.pop()) |value| {
            try received.put(value, {});
            total_received += 1;
        }
    }

    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expectEqual(ProducerCount * ItemsPerProducer, received.count());
}

test "MpscQueue - empty queue operations" {
    var queue = try MpscQueue(i32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    // Test pop on empty queue
    try std.testing.expectEqual(queue.pop(), null);
    try std.testing.expectEqual(queue.pop(), null);

    // Test push-pop-empty cycle
    try std.testing.expect(queue.push(1));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), null);

    // Test multiple push-pop-empty cycles
    try std.testing.expect(queue.push(2));
    try std.testing.expect(queue.push(3));
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expectEqual(queue.pop(), 3);
    try std.testing.expectEqual(queue.pop(), null);
}

test "MpscQueue - alternating empty and full states" {
    var queue = try MpscQueue(i32).init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);

    for (0..5) |i| {
        try std.testing.expectEqual(queue.pop(), null);
        try std.testing.expect(queue.push(@intCast(i)));
        try std.testing.expect(queue.push(@intCast(i + 1)));
        try std.testing.expect(!queue.push(@intCast(i + 2)));
        try std.testing.expectEqual(queue.pop(), @as(i32, @intCast(i)));
        try std.testing.expectEqual(queue.pop(), @as(i32, @intCast(i + 1)));
        try std.testing.expectEqual(queue.pop(), null);
    }
}

test "MpscQueue - wrap around behavior" {
    var queue = try MpscQueue(i32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expect(queue.push(3));
    try std.testing.expect(queue.push(4));
    try std.testing.expectEqual(queue.pop(), 3);
    try std.testing.expectEqual(queue.pop(), 4);
}

test "MpscQueue - different types" {
    var queue = try MpscQueue(f32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1.5));
    try std.testing.expect(queue.push(2.5));
    try std.testing.expectEqual(queue.pop(), 1.5);
    try std.testing.expectEqual(queue.pop(), 2.5);
}

test "MpscQueue - stress test with multiple producers" {
    const ProducerCount = 8;
    const ItemsPerProducer = 50_000;
    var queue = try MpscQueue(u64).init(std.testing.allocator, ProducerCount * 4);
    defer queue.deinit(std.testing.allocator);

    const Producer = struct {
        fn run(q: *MpscQueue(u64), id: u64, results: *std.atomic.Value(u64)) !void {
            var i: u64 = 0;
            while (i < ItemsPerProducer) : (i += 1) {
                while (!q.push(id)) {
                    try std.Thread.yield();
                }
                _ = results.fetchAdd(1, .release);
            }
        }
    };

    var threads: [ProducerCount]std.Thread = undefined;
    var total_pushed = std.atomic.Value(u64).init(0);
    var total_received: u64 = 0;

    // Start producers
    for (0..ProducerCount) |i| {
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{ &queue, i, &total_pushed });
    }

    // Consume items
    while (total_received < ProducerCount * ItemsPerProducer) {
        if (queue.pop()) |_| {
            total_received += 1;
        }
    }

    // Join producers
    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expectEqual(total_pushed.load(.acquire), ProducerCount * ItemsPerProducer);
    try std.testing.expectEqual(total_received, ProducerCount * ItemsPerProducer);
}

/// A single-producer, single-consumer (SPSC) queue.
///
/// This queue is designed for use cases where there is a single producer and a single consumer of the queue.
/// It provides a lock-free and wait-free implementation, making it suitable for high-performance concurrent scenarios.
/// The queue uses a circular buffer to store the elements, and the producer and consumer threads coordinate their access
/// to the buffer using atomic operations to ensure thread safety.
pub fn SpscQueue(comptime T: type) type {
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

        head: usize align(Cache_Line_Size),
        tail: usize align(Cache_Line_Size),
        buffer: Buffer,

        /// Initializes a new `SpscQueue` with the given `capacity`.
        /// The actual capacity of the queue will be rounded up to the nearest power of two.
        /// If the requested capacity is too large, an error is returned.
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
                .head = 0,
                .tail = 0,
                .buffer = .{
                    .entries = entries,
                    .mask = real_capacity - 1,
                },
            };
        }

        /// Pushes a value onto the queue.
        ///
        /// This function attempts to push the given `value` onto the queue. If the queue is not full, the value is added and the function returns `true`. If the queue is full, the function returns `false`.
        ///
        /// The function uses atomic operations to ensure thread safety between the producer and consumer threads.
        pub fn push(self: *Self, value: T) bool {
            const entry = &self.buffer.entries[self.head & self.buffer.mask];
            const diff = @as(isize, @intCast(entry.sequence)) - @as(isize, @intCast(self.head));

            if (diff == 0) {
                entry.value = value;
                entry.sequence = self.head + 1;
                self.head += 1;
                return true;
            }
            return false;
        }

        /// Pops a value from the queue.
        ///
        /// This function attempts to pop a value from the queue. If the queue is not empty, the value is returned. If the queue is empty, `null` is returned.
        ///
        /// The function uses atomic operations to ensure thread safety between the producer and consumer threads.
        pub fn pop(self: *Self) ?T {
            const entry = &self.buffer.entries[self.tail & self.buffer.mask];
            const diff = @as(isize, @intCast(entry.sequence)) - @as(isize, @intCast(self.tail + 1));

            if (diff == 0) {
                const value = entry.value;
                entry.sequence = self.tail + self.buffer.entries.len;
                self.tail += 1;
                return value;
            }
            return null;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.buffer.entries);
        }
    };
}

test "SpscQueue - basic operations" {
    var queue = try SpscQueue(i32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expectEqual(queue.pop(), null);
}

test "SpscQueue - queue full" {
    var queue = try SpscQueue(i32).init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(!queue.push(3));
}

test "SpscQueue - single producer single consumer" {
    const ItemCount = 100_000;
    var queue = try SpscQueue(u64).init(std.testing.allocator, 8);
    defer queue.deinit(std.testing.allocator);

    const Producer = struct {
        fn run(q: *SpscQueue(u64)) !void {
            var i: u64 = 0;
            while (i < ItemCount) : (i += 1) {
                while (!q.push(i)) {
                    try std.Thread.yield();
                }
            }
        }
    };

    const Consumer = struct {
        fn run(q: *SpscQueue(u64)) !void {
            var i: u64 = 0;
            while (i < ItemCount) {
                if (q.pop()) |value| {
                    try std.testing.expectEqual(value, i);
                    i += 1;
                } else {
                    try std.Thread.yield();
                }
            }
        }
    };

    var producer_thread = try std.Thread.spawn(.{}, Producer.run, .{&queue});
    var consumer_thread = try std.Thread.spawn(.{}, Consumer.run, .{&queue});

    producer_thread.join();
    consumer_thread.join();
}

test "SpscQueue - empty queue operations" {
    var queue = try SpscQueue(i32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expectEqual(queue.pop(), null);
    try std.testing.expectEqual(queue.pop(), null);
    try std.testing.expect(queue.push(1));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), null);
}

test "SpscQueue - wrap around behavior" {
    var queue = try SpscQueue(i32).init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expectEqual(queue.pop(), 1);
    try std.testing.expectEqual(queue.pop(), 2);
    try std.testing.expect(queue.push(3));
    try std.testing.expect(queue.push(4));
    try std.testing.expectEqual(queue.pop(), 3);
    try std.testing.expectEqual(queue.pop(), 4);
}

test "SpscQueue - alternating empty and full states" {
    var queue = try SpscQueue(i32).init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);

    for (0..5) |i| {
        try std.testing.expectEqual(queue.pop(), null);
        try std.testing.expect(queue.push(@intCast(i)));
        try std.testing.expect(queue.push(@intCast(i + 1)));
        try std.testing.expect(!queue.push(@intCast(i + 2)));
        try std.testing.expectEqual(queue.pop(), @as(i32, @intCast(i)));
        try std.testing.expectEqual(queue.pop(), @as(i32, @intCast(i + 1)));
        try std.testing.expectEqual(queue.pop(), null);
    }
}

test "SpscQueue - stress test with high throughput" {
    const ItemCount = 1_000_000;
    var queue = try SpscQueue(u64).init(std.testing.allocator, 1024);
    defer queue.deinit(std.testing.allocator);

    const Producer = struct {
        fn run(q: *SpscQueue(u64)) !void {
            var i: u64 = 0;
            while (i < ItemCount) : (i += 1) {
                while (!q.push(i)) {
                    try std.Thread.yield();
                }
            }
        }
    };

    const Consumer = struct {
        fn run(q: *SpscQueue(u64)) !void {
            var expected: u64 = 0;
            while (expected < ItemCount) {
                if (q.pop()) |value| {
                    try std.testing.expectEqual(value, expected);
                    expected += 1;
                }
            }
        }
    };

    var producer_thread = try std.Thread.spawn(.{}, Producer.run, .{&queue});
    var consumer_thread = try std.Thread.spawn(.{}, Consumer.run, .{&queue});

    producer_thread.join();
    consumer_thread.join();
}
