const std = @import("std");
const yaml = @cImport({
    @cInclude("yaml.h");
});
const stdio = @cImport({
    @cInclude("stdio.h");
});

pub fn parseYamlFile(filename: []const u8, show_error: bool) !void {
    var file: *std.c.FILE = undefined;
    var parser: yaml.yaml_parser_t = undefined;
    var event: yaml.yaml_event_t = undefined;
    var done: bool = false;
    var count: usize = 0;

    // std.debug.print("[{}] Parsing '{}': ", .{ 0, filename });

    file = try std.c.fopen(filename + "\x00", "rb");

    // file = try std.c.fopen(filename.ptr, "rb");
    defer _ = std.c.fclose(file);

    if (yaml.yaml_parser_initialize(&parser) == 0) {
        return error.ParserInitializationFailed;
    }
    defer yaml.yaml_parser_delete(&parser);

    yaml.yaml_parser_set_input_file(&parser, file);

    while (!done) {
        if (yaml.yaml_parser_parse(&parser, &event) == 0) {
            if (show_error) {
                std.debug.print("Parse error: {s}\nLine: {} Column: {}\n", .{
                    parser.problem,
                    parser.problem_mark.line + 1,
                    parser.problem_mark.column + 1,
                });
            }
            return error.ParseError;
        }

        done = (event.type == yaml.YAML_STREAM_END_EVENT);

        yaml.yaml_event_delete(&event);

        count += 1;
    }

    std.debug.print("Done. Number of events: {}\n", .{count});
}

test "yaml.zig" {
    try parseYamlFile("clib/libyaml/examples/json.yaml", true);
}
