const std = @import("std");
const yaml = @cImport({
    @cInclude("yaml.h");
});
const stdio = @cImport({
    @cInclude("stdio.h");
});

test "yaml.zig" {
    var parser: yaml.yaml_parser_t = undefined;
    const file = stdio.fopen("test.yaml", "rb");
    _ = yaml.yaml_parser_initialize(&parser);
    yaml.yaml_parser_set_input_file(&parser, file);
    std.debug.print("parser: {any}\n", .{parser});
}