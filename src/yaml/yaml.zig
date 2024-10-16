const std = @import("std");
const yaml = @import("yaml");


pub fn parse() void {
    var parser: yaml.yaml_parser_t = undefined;
    var emitter: yaml.yaml_emitter_t = undefined;
    // var input_event: yaml.yaml_event_t = undefined;
    // var output_event: yaml.yaml_event_t = undefined;
    if (yaml.yaml_parser_initialize(&parser) == 0) {
        std.debug.print("Could not initialize the parser object\n", .{});
    }

    if (yaml.yaml_emitter_initialize(&emitter) == 0) {
        yaml.yaml_parser_delete(&parser);
        std.debug.print("Could not initialize the emitter object\n", .{});
    }
    std.debug.print("parser {}\n", .{parser});
    std.debug.print("emitter {}\n", .{emitter});
}

pub fn testCase() !void {
    const filename = "./clib/libyaml/examples/global-tag.yaml";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Read file contents
    const file_contents = try std.fs.cwd().readFileAlloc(allocator, filename, 1024 * 1024);
    defer allocator.free(file_contents);

    var parser: yaml.yaml_parser_t = undefined;
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    if (yaml.yaml_parser_initialize(&parser) == 0) {
        std.debug.print("Failed to initialize YAML parser\n", .{});
        return;
    }
    defer yaml.yaml_parser_delete(&parser);

    // Set up the parser with the file
    yaml.yaml_parser_set_input_string(&parser, file_contents.ptr, file_contents.len);

    // Parse the YAML file and process it with Zephyrus
    std.debug.print("YAML {}\n", .{parser});

    std.debug.print("YAML file processed successfully\n", .{});

    var event: yaml.yaml_event_t = undefined;
    var done = false;

    while (!done) {
        if (yaml.yaml_parser_parse(&parser, &event) == 0) {
            std.debug.print("Error parsing YAML\n", .{});
            return;
        }

        switch (event.type) {
            yaml.YAML_STREAM_START_EVENT => std.debug.print("Stream start\n", .{}),
            yaml.YAML_STREAM_END_EVENT => {
                std.debug.print("Stream end\n", .{});
                done = true;
            },
            yaml.YAML_SCALAR_EVENT => {
                const value = std.mem.span(@as([*:0]const u8, @ptrCast(event.data.scalar.value)));
                // const value = std.mem.span(@ptrCast([*:0]const u8, event.data.scalar.value));
                std.debug.print("Scalar: {s}\n", .{value});
            },
            yaml.YAML_SEQUENCE_START_EVENT => std.debug.print("Sequence start\n", .{}),
            yaml.YAML_SEQUENCE_END_EVENT => std.debug.print("Sequence end\n", .{}),
            yaml.YAML_MAPPING_START_EVENT => std.debug.print("Mapping start\n", .{}),
            yaml.YAML_MAPPING_END_EVENT => std.debug.print("Mapping end\n", .{}),
            else => {},
        }

        yaml.yaml_event_delete(&event);
    }
}

pub fn parseToken() !void {
    const filename = "./clib/libyaml/examples/json.yaml";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Read file contents
    const file_contents = try std.fs.cwd().readFileAlloc(allocator, filename, 1024 * 1024);
    defer allocator.free(file_contents);

    var parser: yaml.yaml_parser_t = undefined;
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    if (yaml.yaml_parser_initialize(&parser) == 0) {
        std.debug.print("Failed to initialize YAML parser\n", .{});
        return;
    }
    defer yaml.yaml_parser_delete(&parser);

    // Set up the parser with the file
    yaml.yaml_parser_set_input_string(&parser, file_contents.ptr, file_contents.len);

    // Parse the YAML file and process it with Zephyrus
    std.debug.print("YAML {}\n", .{parser});

    std.debug.print("YAML file processed successfully\n", .{});

    var token: yaml.yaml_token_t = undefined;
    while (true) {
        if (yaml.yaml_parser_scan(&parser, &token) == 0) {
            std.debug.print("Error parsing YAML\n", .{});
            return;
        }

        switch (token.type) {
            yaml.YAML_STREAM_START_TOKEN => std.debug.print("STREAM START\n", .{}),
            yaml.YAML_STREAM_END_TOKEN => {
                std.debug.print("STREAM END\n", .{});
                break;
            },
            yaml.YAML_KEY_TOKEN => std.debug.print("KEY\n", .{}),
            yaml.YAML_VALUE_TOKEN => std.debug.print("VALUE\n", .{}),
            yaml.YAML_BLOCK_SEQUENCE_START_TOKEN => std.debug.print("BLOCK SEQUENCE START\n", .{}),
            yaml.YAML_BLOCK_ENTRY_TOKEN => std.debug.print("BLOCK ENTRY\n", .{}),
            yaml.YAML_BLOCK_END_TOKEN => std.debug.print("BLOCK END\n", .{}),
            yaml.YAML_FLOW_SEQUENCE_START_TOKEN => std.debug.print("FLOW SEQUENCE START\n", .{}),
            yaml.YAML_FLOW_SEQUENCE_END_TOKEN => std.debug.print("FLOW SEQUENCE END\n", .{}),
            yaml.YAML_FLOW_MAPPING_START_TOKEN => std.debug.print("FLOW MAPPING START\n", .{}),
            yaml.YAML_FLOW_MAPPING_END_TOKEN => std.debug.print("FLOW MAPPING END\n", .{}),
            yaml.YAML_SCALAR_TOKEN => {
                const value = std.mem.span(@as([*:0]const u8, @ptrCast(token.data.scalar.value)));
                std.debug.print("SCALAR: {s}\n", .{value});
            },
            yaml.YAML_DOCUMENT_START_TOKEN => std.debug.print("DOCUMENT START\n", .{}),
            yaml.YAML_DOCUMENT_END_TOKEN => std.debug.print("DOCUMENT END\n", .{}),
            else => std.debug.print("OTHER TOKEN: {}\n", .{token.type}),
        }

        yaml.yaml_token_delete(&token);
    }
}

test "yaml" {
    try parseToken();
}