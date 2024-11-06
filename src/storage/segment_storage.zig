const std = @import("std");
const fs = std.fs;
const mmap = std.c.mmap;
const munmap = std.c.munmap;
const crc32 = std.hash.Crc32;
const MAP = std.c.MAP;

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

pub const Segment = struct {
    base_offset: u64,
    data_file: SegmentFile,
    index_file: SegmentFile,
    mutex: std.Thread.Mutex,

    pub fn init(dir: []const u8, base_offset: u64, config: Log.Config, allocator: std.mem.Allocator) !Segment {
        const data_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{d}.data",
            .{ dir, base_offset },
        );
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
    pub fn append(self: *Segment, record: Record) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Write record header
        try self.writeHeader(record);

        // Write data
        const data_offset = self.data_file.position;
        @memcpy(
            self.data_file.mmap_data[data_offset..][0..record.data.len],
            record.data,
        );

        // Update index
        try self.updateIndex(record.offset, data_offset);

        self.data_file.position += record.data.len;
        return record.offset;
    }
    fn writeHeader(self: *Segment, record: Record) !void {
        var header: [16]u8 = undefined;
        std.mem.writeInt(u32, header[0..4], record.crc, .little);
        std.mem.writeInt(u32, header[4..8], record.size, .little);
        std.mem.writeInt(i64, header[8..16], record.timestamp, .little);

        const pos = self.data_file.position;
        @memcpy(self.data_file.mmap_data[pos..][0..16], &header);
        self.data_file.position += 16;
    }

    fn updateIndex(self: *Segment, offset: u64, position: u64) !void {
        const relative_offset = offset - self.base_offset;
        const index_position = relative_offset * @sizeOf(u64);

        // Write position to index file
        std.mem.writeInt(u64, self.index_file.mmap_data[index_position..][0..8], position, .little);

        self.index_file.position = @max(self.index_file.position, index_position + @sizeOf(u64));
    }

    pub fn read(self: *Segment, offset: u64) !Record {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Read from index to get position
        const position = try self.readIndex(offset);

        // Read record header
        const header = try self.readHeader(position);

        // Read data
        const data = self.data_file.mmap_data[position + 16 ..][0..header.size];

        // Add CRC validation in read() method
        if (crc32.hash(data) != header.crc) {
            return error.InvalidCrc;
        }

        return Record{
            .offset = offset,
            .crc = header.crc,
            .size = header.size,
            .timestamp = header.timestamp,
            .data = data,
        };
    }

    fn readHeader(self: *Segment, position: u64) !struct { crc: u32, size: u32, timestamp: i64 } {
        const header_data = self.data_file.mmap_data[position..][0..16];

        return .{
            .crc = @as(u32, @bitCast(std.mem.readInt(u32, header_data[0..4], .little))),
            .size = @as(u32, @bitCast(std.mem.readInt(u32, header_data[4..8], .little))),
            .timestamp = @as(i64, @bitCast(std.mem.readInt(i64, header_data[8..16], .little))),
        };
    }

    fn readIndex(self: *Segment, offset: u64) !u64 {
        const relative_offset = offset - self.base_offset;
        const index_position = relative_offset * @sizeOf(u64);

        if (index_position >= self.index_file.position) {
            return error.OffsetNotFound;
        }

        return std.mem.readInt(u64, self.index_file.mmap_data[index_position..][0..8], .little);
    }

    pub fn deinit(self: *Segment) void {
        self.data_file.deinit();
        self.index_file.deinit();
    }
};

pub const SegmentError = error{
    InvalidCrc,
    OffsetNotFound,
    InvalidConfig,
    BufferOverflow,
};

pub const Log = struct {
    dir: []const u8,
    segments: std.ArrayList(Segment),
    config: Config,
    mutex: std.Thread.Mutex,

    pub const Config = struct {
        segment_size: u64,
        index_size: u64,
        max_segments: u32,
        compress: bool,

        pub fn validate(self: Config) SegmentError!void {
            if (self.segment_size == 0 or self.index_size == 0 or self.max_segments == 0) {
                return SegmentError.InvalidConfig;
            }
            if (self.segment_size > std.math.maxInt(u32)) {
                return SegmentError.InvalidConfig;
            }
        }
    };

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

    pub fn read(self: *Log, offset: u64) !Record {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.segments.items) |*segment| {
            if (offset >= segment.base_offset and
                offset < segment.base_offset + segment.data_file.position)
            {
                return segment.read(offset);
            }
        }

        return error.OffsetNotFound;
    }

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

    fn shouldRotate(self: *Log) bool {
        if (self.segments.items.len == 0) {
            return true;
        }

        const current = &self.segments.items[self.segments.items.len - 1];
        const size = current.data_file.position;

        return size >= self.config.segment_size;
    }

    fn compress(self: *Log, data: []const u8) ![]const u8 {
        if (data.len > self.config.segment_size) {
            return SegmentError.BufferOverflow;
        }
        var out = std.ArrayList(u8).init(self.segments.allocator);
        var comp = try std.compress.zlib.compressor(out.writer(), .{});
        _ = try comp.write(data);
        try comp.flush();
        try comp.finish();

        return out.toOwnedSlice();
    }

    fn decompress(self: *Log, data: []const u8) ![]const u8 {
        var decomp = std.compress.zlib.decompressor(std.io.fixedBufferStream(data).reader());
        defer decomp.deinit();

        var out = std.ArrayList(u8).init(self.segments.allocator);
        try decomp.decompress(data, &out);

        return out.toOwnedSlice();
    }

    pub fn deinit(self: *Log) void {
        for (self.segments.items) |*segment| {
            segment.deinit();
        }
        self.segments.deinit();
    }
};
