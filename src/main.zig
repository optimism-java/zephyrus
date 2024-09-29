const std = @import("std");
const preset = @import("presets/preset.zig");
const bellatrix = @import("consensus/bellatrix/types.zig");
const types = @import("consensus/types.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    // print mainnet preset
    try stdout.print("{}\n", .{preset.mainnet_preset});
    try bw.flush(); // don't forget to flush!

    const a = types.HistoricalBatchMainnet{
        .block_roots = undefined,
        .state_roots = undefined,
    };

    const b = bellatrix.ExecutionPayloadHeaderMainnet{
        .parent_hash = undefined,
        .fee_recipient = undefined,
        .state_root = undefined,
        .receipts_root = undefined,
        .logs_bloom = undefined,
        .prev_randao = undefined,
        .block_number = 21,
        .gas_used = 0,
        .gas_limit = 0,
        .timestamp = 0,
        .extra_data = undefined,
        .base_fee_per_gas = 0,
        .block_hash = undefined,
    };
    try stdout.print("{}\n", .{a});
    try stdout.print("{}\n", .{b});
}
