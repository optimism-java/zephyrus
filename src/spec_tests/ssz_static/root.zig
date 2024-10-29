const std = @import("std");
const testing = std.testing;
const ssz = @import("../../ssz/ssz.zig");
const types = @import("../../consensus/types.zig");
const snappy = @import("../../snappy/snappy.zig");

const Yaml = @import("../../yaml/yaml.zig").Yaml;

const gpa = testing.allocator;

/// Loads and parses a YAML file into a Yaml object
/// Parameters:
///   file_path: Path to the YAML file to load
/// Returns:
///   Parsed Yaml object or error
fn loadFromFile(file_path: []const u8) !Yaml {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const source = try file.readToEndAlloc(gpa, std.math.maxInt(u32));
    defer gpa.free(source);

    return Yaml.load(gpa, source);
}
// load root.yml in spec test
const Roots = struct {
    root: [32]u8,
};
// test cases for all phases
const CommonUnion = union {
    Fork: types.Fork,
};

test "ssz static" {
    const testPath = "consensus-spec-tests/tests/mainnet";
    const gpa1 = testing.allocator;
    const fields = @typeInfo(CommonUnion).@"union".fields;
    inline for (fields) |field| {
        const fieldType = field.type;
        const fieldName = field.name;
        const ssz_type_path = try std.fmt.allocPrint(gpa1, "{s}/phase0/ssz_static/{s}", .{ testPath, fieldName });

        var dirs = try getLeafDirs(gpa1, ssz_type_path);

        // deinit the dirs array
        defer {
            for (dirs.items) |item| {
                gpa1.free(item);
            }
            dirs.deinit();
        }

        for (dirs.items) |dir| {
            try testSSZStatic(dir, fieldType);
        }
    }
}

/// Recursively finds all leaf directories (directories with no subdirectories) starting from the given path
/// Parameters:
///   allocator: Memory allocator for dynamic allocations
///   path: Starting directory path to search from
/// Returns:
///   ArrayList containing paths to all leaf directories
fn getLeafDirs(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList([]const u8) {
    var leafDirs = std.ArrayList([]const u8).init(allocator);
    // defer leafDirs.deinit();
    var list = std.ArrayList([]const u8).init(allocator);
    defer {
        for (list.items) |item| {
            allocator.free(item);
        }
        list.deinit();
    }
    try list.append(path);

    var index: u32 = 0;

    while (index < list.items.len) {
        var hasSubDir = false;
        const currentPath = list.items[index];
        var dir = try std.fs.cwd().openDir(currentPath, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();

        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                hasSubDir = true;
                const fullPath = try std.fs.path.join(allocator, &[_][]const u8{ currentPath, entry.name });
                try list.append(fullPath);
            }
        }
        if (!hasSubDir) {
            try leafDirs.append(try allocator.dupe(u8, currentPath));
        }
        index += 1;
    }

    return leafDirs;
}

/// Tests SSZ (Simple Serialize) static functionality by performing:
/// 1. YAML parsing
/// 2. Hash tree root verification
/// 3. SSZ encoding/decoding with snappy compression
/// Parameters:
///   path: Directory path containing test files
///   t: Type to test SSZ operations against
fn testSSZStatic(path: []const u8, t: type) !void {
    // parse from yaml
    const valueFile = try std.fmt.allocPrint(testing.allocator, "{s}/value.yaml", .{path});
    defer testing.allocator.free(valueFile);
    var parsed = try loadFromFile(valueFile);
    defer parsed.deinit();
    const fork = try parsed.parse(t);
    // test hash tree root
    var out: [32]u8 = [_]u8{0} ** 32;
    try ssz.hashTreeRoot(fork, &out, testing.allocator);
    const rootFile = try std.fmt.allocPrint(testing.allocator, "{s}/roots.yaml", .{path});
    defer testing.allocator.free(rootFile);
    var rootData = try loadFromFile(rootFile);
    defer rootData.deinit();
    const root = try rootData.parse(Roots);
    const expect: [32]u8 = root.root;
    try std.testing.expect(std.mem.eql(u8, out[0..], expect[0..]));
    // test ssz encode
    const file_path = try std.fmt.allocPrint(testing.allocator, "{s}/serialized.ssz_snappy", .{path});
    defer testing.allocator.free(file_path);
    const file_contents = try std.fs.cwd().readFileAlloc(testing.allocator, file_path, std.math.maxInt(usize));
    defer testing.allocator.free(file_contents);
    const decoded_data = try snappy.decode(testing.allocator, file_contents);
    defer testing.allocator.free(decoded_data);
    const encode = try ssz.encodeSSZ(testing.allocator, fork);
    defer testing.allocator.free(encode);
    try std.testing.expect(std.mem.eql(u8, encode, decoded_data));

    // test ssz decode
    const decode = try ssz.decodeSSZ(t, decoded_data);
    try std.testing.expectEqualDeep(decode, fork);
}
