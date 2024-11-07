const std = @import("std");
const fs = std.fs;
const mmap = std.c.mmap;
const munmap = std.c.munmap;
const crc32 = std.hash.Crc32;
const MAP = std.c.MAP;
const testing = std.testing;

/// A record in the segment storage, containing metadata and data.
pub const Record = struct {
    offset: u64,
    crc: u32,
    size: u32,
    timestamp: i64,
    data: []const u8,

    pub fn init(data: []const u8) Record {
        return .{
            .offset = 0,
            .crc = std.hash.Crc32.hash(data),
            .size = @intCast(data.len),
            .timestamp = std.time.milliTimestamp(),
            .data = data,
        };
    }
};

/// A file-backed memory-mapped segment used for storing log records.
/// The segment file contains both the data and index for the log records.
/// The data file is memory-mapped for efficient access, and the index file
/// is used to quickly locate records within the data file.
pub const SegmentFile = struct {
    file: fs.File,
    mmap_data: []u8,
    position: u64,

    pub fn init(path: []const u8, size: u64) !SegmentFile {
        const file = try fs.createFileAbsolute(path, .{
            .read = true,
            .truncate = false,
        });
        try file.setEndPos(size);

        const mmap_data = mmap(null, size, std.c.PROT.READ | std.c.PROT.WRITE, .{ .TYPE = .SHARED }, file.handle, 0);
        return .{
            .file = file,
            .mmap_data = @as([*]u8, @ptrCast(mmap_data))[0..size],
            .position = 0,
        };
    }

    pub fn deinit(self: *SegmentFile) void {
        self.file.sync() catch {
            // ignore
        };
        _ = munmap(@alignCast(@ptrCast(self.mmap_data.ptr)), self.mmap_data.len);
        self.file.close();
    }
};

/// A file-backed memory-mapped segment used for storing log records.
/// The segment file contains both the data and index for the log records.
/// The data file is memory-mapped for efficient access, and the index file
/// is used to quickly locate records within the data file.
pub const Segment = struct {
    base_offset: u64,
    data_file: SegmentFile,
    index_file: SegmentFile,
    mutex: std.Thread.Mutex,

    /// Initializes a new Segment with the given directory, base offset, configuration, and allocator.
    ///
    /// The Segment struct represents a file-backed memory-mapped segment used for storing log records.
    /// The segment file contains both the data and index for the log records. The data file is memory-mapped
    /// for efficient access, and the index file is used to quickly locate records within the data file.
    ///
    /// This function creates the necessary data and index files for the Segment and returns a new Segment instance.
    ///
    /// @param dir The directory where the segment files will be stored.
    /// @param base_offset The base offset for the segment.
    /// @param config The configuration for the log.
    /// @param allocator The allocator to use for any dynamic memory allocations.
    /// @return A new Segment instance.
    pub fn init(dir: []const u8, base_offset: u64, config: Log.Config, allocator: std.mem.Allocator) !Segment {
        const data_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{d}.data",
            .{ dir, base_offset },
        );
        std.debug.print("data_path: {s}\n", .{data_path});
        defer allocator.free(data_path);

        const index_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{d}.index",
            .{ dir, base_offset },
        );
        defer allocator.free(index_path);

        const data_file = try SegmentFile.init(data_path, config.segment_size);
        const index_file = try SegmentFile.init(index_path, config.index_size);

        return .{
            .base_offset = base_offset,
            .data_file = data_file,
            .index_file = index_file,
            .mutex = std.Thread.Mutex{},
        };
    }
    /// Appends a new record to the segment.
    ///
    /// This function writes the record header and data to the segment's data file, and updates the segment's index file
    /// to track the location of the record within the data file.
    ///
    /// If there is not enough space in the data file to write the record, this function returns `SegmentError.SegmentFull`.
    ///
    /// @param self A mutable reference to the Segment instance.
    /// @param record The Record to append to the segment.
    /// @return The offset of the appended record within the segment.
    pub fn append(self: *Segment, record: Record) !u64 {
        // Check if there's enough space for header (16 bytes) + data
        if (self.data_file.position + 16 + record.data.len > self.data_file.mmap_data.len) {
            return SegmentError.SegmentFull;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        const next_offset = self.base_offset + (self.index_file.position / @sizeOf(u64));
        const data_offset = self.data_file.position;

        try self.writeHeader(record);
        @memcpy(
            self.data_file.mmap_data[data_offset + 16 ..][0..record.data.len],
            record.data,
        );

        try self.updateIndex(next_offset, data_offset);
        self.data_file.position += record.data.len + 16;
        return next_offset;
    }
    /// Writes the header of a record to the segment's data file.
    ///
    /// This function writes the CRC, size, and timestamp of the record to a 16-byte header, and then copies that header
    /// to the current position in the data file. It also updates the position of the data file to point to the end of the
    /// header.
    ///
    /// @param self A mutable reference to the Segment instance.
    /// @param record The Record whose header should be written.
    fn writeHeader(self: *Segment, record: Record) !void {
        var header: [16]u8 = undefined;
        std.mem.writeInt(u32, header[0..4], record.crc, .little);
        std.mem.writeInt(u32, header[4..8], record.size, .little);
        std.mem.writeInt(i64, header[8..16], record.timestamp, .little);

        const pos = self.data_file.position;
        @memcpy(self.data_file.mmap_data[pos..][0..16], &header);
        self.data_file.position += 16;
    }

    /// Updates the index file with the position of the record in the data file.
    ///
    /// This function calculates the relative offset of the record within the segment, and then writes the position of the
    /// record in the data file to the corresponding index entry. It also updates the position of the index file to point
    /// to the end of the index data.
    ///
    /// @param self A mutable reference to the Segment instance.
    /// @param offset The offset of the record within the segment.
    /// @param position The position of the record in the data file.
    fn updateIndex(self: *Segment, offset: u64, position: u64) !void {
        const relative_offset = offset - self.base_offset;
        const index_position = relative_offset * @sizeOf(u64);

        // Write position to index file
        std.mem.writeInt(u64, self.index_file.mmap_data[index_position..][0..8], position, .little);

        self.index_file.position = @max(self.index_file.position, index_position + @sizeOf(u64));
    }

    /// Reads a record from the segment at the specified offset.
    ///
    /// This function first acquires a lock on the segment's mutex to ensure thread safety. It then checks if the requested
    /// offset is within the range of the segment's base offset. If not, it returns a SegmentError.OffsetNotFound error.
    ///
    /// Next, it reads the index file to get the position of the record in the data file. It then reads the record header,
    /// which contains the CRC, size, and timestamp of the record. It validates the CRC of the record data and returns a
    /// Record struct containing the record's offset, CRC, size, timestamp, and data.
    ///
    /// @param self A mutable reference to the Segment instance.
    /// @param offset The offset of the record within the segment.
    /// @return The record at the specified offset, or a SegmentError if the record could not be read.
    pub fn read(self: *Segment, offset: u64) !Record {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (offset < self.base_offset) {
            return SegmentError.OffsetNotFound;
        }

        // Read from index to get position
        const position = try self.readIndex(offset);

        // Read record header
        const header = try self.readHeader(position);

        // Read data with bounds checking
        if (position + 16 + header.size > self.data_file.mmap_data.len) {
            return SegmentError.InvalidCrc;
        }
        const data = self.data_file.mmap_data[position + 16 ..][0..header.size];

        // CRC validation
        if (crc32.hash(data) != header.crc) {
            return SegmentError.InvalidCrc;
        }

        return Record{
            .offset = offset,
            .crc = header.crc,
            .size = header.size,
            .timestamp = header.timestamp,
            .data = data,
        };
    }

    /// Reads the header of a record from the segment's data file at the specified position.
    ///
    /// The header contains the CRC, size, and timestamp of the record.
    ///
    /// @param self A mutable reference to the Segment instance.
    /// @param position The position of the record header in the data file.
    /// @return A struct containing the CRC, size, and timestamp of the record.
    fn readHeader(self: *Segment, position: u64) !struct { crc: u32, size: u32, timestamp: i64 } {
        const header_data = self.data_file.mmap_data[position..][0..16];

        return .{
            .crc = @as(u32, @bitCast(std.mem.readInt(u32, header_data[0..4], .little))),
            .size = @as(u32, @bitCast(std.mem.readInt(u32, header_data[4..8], .little))),
            .timestamp = @as(i64, @bitCast(std.mem.readInt(i64, header_data[8..16], .little))),
        };
    }

    /// Reads the index file to find the position of a record in the data file given an offset.
    ///
    /// The index file contains the positions of records in the data file. This function
    /// calculates the index position based on the given offset, reads the index file,
    /// and returns the position of the record in the data file.
    ///
    /// @param self A mutable reference to the Segment instance.
    /// @param offset The offset of the record to look up.
    /// @return The position of the record in the data file, or SegmentError.OffsetNotFound
    ///         if the offset is not found in the index.
    fn readIndex(self: *Segment, offset: u64) !u64 {
        const relative_offset = offset - self.base_offset;
        const index_position = relative_offset * @sizeOf(u64);

        if (index_position >= self.index_file.position) {
            return SegmentError.OffsetNotFound;
        }

        return std.mem.readInt(u64, self.index_file.mmap_data[index_position..][0..8], .little);
    }

    /// Deinitializes the Segment instance by deinitializing the data and index files.
    ///
    /// This function should be called when the Segment is no longer needed to free up
    /// any resources associated with the Segment.
    pub fn deinit(self: *Segment) void {
        self.data_file.deinit();
        self.index_file.deinit();
    }
};

/// Defines the set of errors that can occur when working with segments.
///
/// - `InvalidCrc`: The CRC of a record is invalid.
/// - `OffsetNotFound`: The requested offset was not found in the index.
/// - `InvalidConfig`: The configuration for the segment storage is invalid.
/// - `BufferOverflow`: The data to be appended exceeds the maximum segment size.
/// - `SegmentFull`: The segment has reached its maximum capacity.
pub const SegmentError = error{
    InvalidCrc,
    OffsetNotFound,
    InvalidConfig,
    BufferOverflow,
    SegmentFull,
};

/// Represents a log storage system that manages segments of data.
///
/// The `Log` struct is responsible for managing the storage of data in segments. It provides
/// functionality for appending data to the log, rotating segments when necessary, and
/// compressing data. The `Log` struct also manages the configuration for the segment
/// storage, including the segment size, index size, and maximum number of segments.
pub const Log = struct {
    dir: []const u8,
    segments: std.ArrayList(Segment),
    config: Config,
    mutex: std.Thread.Mutex,

    /// Defines the configuration for the segment storage system.
    ///
    /// The `Config` struct contains the settings that control the behavior of the segment
    /// storage system, including the segment size, index size, maximum number of segments,
    /// and whether data should be compressed.
    ///
    /// The `validate` function ensures that the configuration settings are valid, and returns
    /// an error if any of the settings are invalid.
    pub const Config = struct {
        segment_size: u64,
        index_size: u64,
        max_segments: u32,
        compress: bool,

        /// Validates the configuration settings for the segment storage system.
        ///
        /// This function ensures that the configuration settings are valid, and returns an error
        /// if any of the settings are invalid. Specifically, it checks that the `segment_size`,
        /// `index_size`, and `max_segments` fields are all non-zero, and that the `segment_size`
        /// does not exceed the maximum value for a `u32`.
        pub fn validate(self: Config) SegmentError!void {
            if (self.segment_size == 0 or self.index_size == 0 or self.max_segments == 0) {
                return SegmentError.InvalidConfig;
            }
            if (self.segment_size > std.math.maxInt(u32)) {
                return SegmentError.InvalidConfig;
            }
        }
    };

    /// Initializes a new `Log` instance with the provided directory and configuration.
    ///
    /// This function creates a new `Log` instance with the specified directory and configuration.
    /// It first validates the configuration using the `Config.validate` function, and then creates
    /// a new `std.ArrayList(Segment)` to store the log segments. The `std.Thread.Mutex` is also
    /// initialized for synchronizing access to the log.
    ///
    /// - Parameters:
    ///   - `dir`: The directory where the log segments will be stored.
    ///   - `config`: The configuration settings for the log storage system.
    ///   - `allocator`: The memory allocator to use for the `std.ArrayList(Segment)`.
    /// - Returns: A new `Log` instance, or an error if the configuration is invalid or the directory
    ///   cannot be created.
    pub fn init(dir: []const u8, config: Config, allocator: std.mem.Allocator) !Log {
        try config.validate();
        try fs.makeDirAbsolute(dir);

        return .{
            .dir = dir,
            .segments = std.ArrayList(Segment).init(allocator),
            .config = config,
            .mutex = std.Thread.Mutex{},
        };
    }

    /// Appends the given data to the log.
    ///
    /// If the data length exceeds the configured segment size, this function will return a `SegmentError.BufferOverflow` error.
    ///
    /// This function acquires the log's mutex, appends the data to the last segment, and releases the mutex. If there are no segments or the last segment should be rotated, this function will call `rotate()` to create a new segment.
    ///
    /// - Parameter data: The data to append to the log.
    /// - Returns: The offset of the appended record in the log, or a `SegmentError` if the operation fails.
    pub fn append(self: *Log, data: []const u8) !u64 {
        if (data.len > self.config.segment_size) {
            return SegmentError.BufferOverflow;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.segments.items.len == 0 or self.shouldRotate()) {
            try self.rotate();
        }

        var record = Record.init(data);
        if (self.config.compress) {
            record.data = try self.compress(data);
        }

        const last_segment = &self.segments.items[self.segments.items.len - 1];
        return last_segment.append(record);
    }

    /// Acquires the log's mutex and reads the record at the given offset.
    ///
    /// If the offset is not found in any of the log's segments, this function will return a `SegmentError.OffsetNotFound` error.
    ///
    /// - Parameter offset: The offset of the record to read.
    /// - Returns: The record at the given offset, or a `SegmentError` if the operation fails.
    pub fn read(self: *Log, offset: u64) SegmentError!Record {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.segments.items) |*segment| {
            if (offset >= segment.base_offset and
                offset < segment.base_offset + segment.data_file.position)
            {
                return segment.read(offset);
            }
        }

        return SegmentError.OffsetNotFound;
    }

    /// Rotates the log by creating a new segment.
    ///
    /// This function is called when the last segment in the log has reached its maximum size, or when the log has no segments. It creates a new segment with the appropriate base offset and adds it to the list of segments. If the number of segments exceeds the configured maximum, the oldest segment is removed and deinitialized.
    fn rotate(self: *Log) !void {
        const base_offset = if (self.segments.items.len == 0)
            0
        else
            self.segments.items[self.segments.items.len - 1].base_offset +
                self.segments.items[self.segments.items.len - 1].data_file.position;

        const segment = try Segment.init(self.dir, base_offset, self.config, self.segments.allocator);
        try self.segments.append(segment);

        if (self.segments.items.len > self.config.max_segments) {
            var oldest = self.segments.orderedRemove(0);
            oldest.deinit();
        }
    }

    /// Determines if the log should be rotated to a new segment.
    ///
    /// This function checks if the last segment in the log has reached its maximum size, or if the log has no segments. If either of these conditions is true, the log should be rotated to a new segment.
    ///
    /// - Returns: `true` if the log should be rotated, `false` otherwise.
    fn shouldRotate(self: *Log) bool {
        if (self.segments.items.len == 0) {
            return true;
        }

        const current = &self.segments.items[self.segments.items.len - 1];
        const size = current.data_file.position;

        return size >= self.config.segment_size;
    }

    /// Compresses the given data using zlib compression.
    ///
    /// If the length of the data exceeds the configured segment size, this function will return a `SegmentError.BufferOverflow` error.
    ///
    /// The compressed data is returned as an owned slice of bytes.
    fn compress(self: *Log, data: []const u8) ![]const u8 {
        if (data.len > self.config.segment_size) {
            return SegmentError.BufferOverflow;
        }

        var out = std.ArrayList(u8).init(self.segments.allocator);
        errdefer out.deinit();

        var comp = try std.compress.zlib.compressor(out.writer(), .{});
        const written = try comp.write(data);
        std.debug.assert(written == data.len);
        try comp.finish();

        return out.toOwnedSlice();
    }

    /// Decompresses the given compressed data using zlib decompression.
    ///
    /// The compressed data is expected to be in the zlib format. This function will decompress the data and return the decompressed data as an owned slice of bytes.
    ///
    /// If the decompression fails for any reason, this function will return a `SegmentError.DecompressionFailed` error.
    fn decompress(self: *Log, data: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(data);
        var decomp = std.compress.zlib.decompressor(fbs.reader());

        var out = std.ArrayList(u8).init(self.segments.allocator);
        defer out.deinit();

        try decomp.reader().readAllArrayList(&out, std.math.maxInt(usize));
        return out.toOwnedSlice();
    }

    /// Deinitializes the Log, freeing all resources associated with it.
    /// This function iterates through all the segments in the Log and calls
    /// `deinit()` on each one, then deinitializes the segments array itself.
    pub fn deinit(self: *Log) void {
        for (self.segments.items) |*segment| {
            segment.deinit();
        }
        self.segments.deinit();
    }
};

test "Record initialization" {
    const test_data = "test data";
    const record = Record.init(test_data);

    try testing.expect(record.offset == 0);
    try testing.expect(record.size == test_data.len);
    try testing.expect(record.crc == std.hash.Crc32.hash(test_data));
    try testing.expect(record.data.len == test_data.len);
    try testing.expectEqualSlices(u8, record.data, test_data);
}

test "SegmentFile initialization and cleanup" {
    const test_dir = try std.fs.cwd().realpathAlloc(testing.allocator, ".");
    const test_path = try std.fs.path.join(testing.allocator, &.{ test_dir, "test_segment.data" });
    defer testing.allocator.free(test_path);
    defer testing.allocator.free(test_dir);

    const size: u64 = 1024;

    std.debug.print("test_path: {s}\n", .{test_path});
    var segment_file = try SegmentFile.init(test_path, size);
    defer segment_file.deinit();

    try testing.expect(segment_file.position == 0);
    try testing.expect(segment_file.mmap_data.len == size);
    try std.fs.deleteFileAbsolute(test_path);
}

test "Segment append and read" {
    const test_dir = "test_segment_dir";
    try std.fs.cwd().makeDir(test_dir);
    defer std.fs.cwd().deleteTree(test_dir) catch unreachable;
    const base_offset: u64 = 0;
    const config = Log.Config{
        .segment_size = 1024,
        .index_size = 1024,
        .max_segments = 10,
        .compress = false,
    };

    const test_absolute_dir = try std.fs.cwd().realpathAlloc(testing.allocator, test_dir);
    defer testing.allocator.free(test_absolute_dir);
    var segment = try Segment.init(test_absolute_dir, base_offset, config, testing.allocator);
    defer segment.deinit();

    const test_data = "test record data";
    const record = Record.init(test_data);
    const offset = try segment.append(record);

    const read_record = try segment.read(offset);
    try testing.expectEqualSlices(u8, read_record.data, test_data);
    try testing.expect(read_record.crc == record.crc);
    try testing.expect(read_record.size == record.size);
}

test "Log compression" {
    const test_dir = try std.fs.cwd().realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(test_dir);

    const test_path = try std.fs.path.join(testing.allocator, &.{ test_dir, "test_compression_dir" });
    defer testing.allocator.free(test_path);

    std.fs.deleteTreeAbsolute(test_path) catch unreachable;

    const config = Log.Config{
        .segment_size = 1024,
        .index_size = 1024,
        .max_segments = 10,
        .compress = true,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var log = try Log.init(test_path, config, allocator);
    defer {
        log.deinit();
        std.fs.deleteTreeAbsolute(test_path) catch unreachable;
    }

    const test_data = "test compression data";
    const compressed = try log.compress(test_data);
    defer allocator.free(compressed);

    const decompressed = try log.decompress(compressed);
    defer allocator.free(decompressed);

    try testing.expectEqualStrings(test_data, decompressed);
}

test "Log initialization and rotation" {
    const test_dir = try std.fs.cwd().realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(test_dir);

    const test_path = try std.fs.path.join(testing.allocator, &.{ test_dir, "test_log_rotation" });
    defer testing.allocator.free(test_path);

    std.fs.deleteTreeAbsolute(test_path) catch {};

    const config = Log.Config{
        .segment_size = 64,
        .index_size = 1024,
        .max_segments = 2,
        .compress = false,
    };

    var log = try Log.init(test_path, config, testing.allocator);
    defer {
        log.deinit();
        std.fs.deleteTreeAbsolute(test_path) catch {};
    }

    const test_data = "test";
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        _ = try log.append(test_data);
    }

    try testing.expect(log.segments.items.len == 2);
}

test "Log concurrent append and read" {
    const test_dir = try std.fs.cwd().realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(test_dir);

    const test_path = try std.fs.path.join(testing.allocator, &.{ test_dir, "test_concurrent" });
    defer testing.allocator.free(test_path);

    std.fs.deleteTreeAbsolute(test_path) catch {};

    const config = Log.Config{
        .segment_size = 1024,
        .index_size = 1024,
        .max_segments = 2,
        .compress = false,
    };

    var log = try Log.init(test_path, config, testing.allocator);
    defer {
        log.deinit();
        std.fs.deleteTreeAbsolute(test_path) catch {};
    }

    const ThreadContext = struct {
        log: *Log,
        offset: u64 = 0,
    };

    var ctx = ThreadContext{ .log = &log };

    const writer_thread = try std.Thread.spawn(.{}, struct {
        fn write(thread_ctx: *ThreadContext) !void {
            const data = "test data";
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                thread_ctx.offset = try thread_ctx.log.append(data);
                std.time.sleep(1 * std.time.ns_per_ms);
            }
        }
    }.write, .{&ctx});
    const reader_thread = try std.Thread.spawn(.{}, struct {
        fn read(thread_ctx: *ThreadContext) !void {
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                if (thread_ctx.offset > 0) {
                    const record = try thread_ctx.log.read(thread_ctx.offset);
                    try testing.expectEqualStrings("test data", record.data);
                }
                std.time.sleep(1 * std.time.ns_per_ms);
            }
        }
    }.read, .{&ctx});

    writer_thread.join();
    reader_thread.join();
}

test "Log concurrent append, read and rotation" {
    const test_dir = try std.fs.cwd().realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(test_dir);

    const test_path = try std.fs.path.join(testing.allocator, &.{ test_dir, "test_concurrent_rotation" });
    defer testing.allocator.free(test_path);

    std.fs.deleteTreeAbsolute(test_path) catch {};

    const config = Log.Config{
        .segment_size = 64,
        .index_size = 1024,
        .max_segments = 2,
        .compress = false,
    };

    var log = try Log.init(test_path, config, testing.allocator);
    defer {
        log.deinit();
        std.fs.deleteTreeAbsolute(test_path) catch {};
    }

    const ThreadContext = struct {
        log: *Log,
        offsets: *std.ArrayList(u64),
        mutex: std.Thread.Mutex,
    };

    var offsets = std.ArrayList(u64).init(testing.allocator);
    defer offsets.deinit();

    var ctx = ThreadContext{
        .log = &log,
        .offsets = &offsets,
        .mutex = std.Thread.Mutex{},
    };

    const writer_thread = try std.Thread.spawn(.{}, struct {
        fn write(thread_ctx: *ThreadContext) !void {
            const data = "test";
            var i: usize = 0;
            while (i < 20) : (i += 1) {
                const offset = try thread_ctx.log.append(data);
                thread_ctx.mutex.lock();
                try thread_ctx.offsets.append(offset);
                thread_ctx.mutex.unlock();
                std.time.sleep(5 * std.time.ns_per_ms);
            }
        }
    }.write, .{&ctx});

    const reader_thread = try std.Thread.spawn(.{}, struct {
        fn read(thread_ctx: *ThreadContext) !void {
            var i: usize = 0;
            while (i < 20) : (i += 1) {
                thread_ctx.mutex.lock();
                if (thread_ctx.offsets.items.len > 0) {
                    const offset = thread_ctx.offsets.items[0];
                    thread_ctx.mutex.unlock();
                    if (thread_ctx.log.read(offset)) |record| {
                        try testing.expectEqualStrings("test", record.data);
                    } else |_| {}
                } else {
                    thread_ctx.mutex.unlock();
                }
                std.time.sleep(5 * std.time.ns_per_ms);
            }
        }
    }.read, .{&ctx});

    writer_thread.join();
    reader_thread.join();

    try testing.expect(log.segments.items.len > 1);
}
