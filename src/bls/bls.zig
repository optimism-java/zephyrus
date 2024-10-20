const std = @import("std");
const bls = @cImport({
    @cDefine("BLS_ETH", "1");
    @cInclude("bls/bls384_256.h");
});

var mutex = std.Thread.Mutex{};

pub fn init() void {
    mutex.lock();
    defer mutex.unlock();
    std.debug.print(" {}\n", .{bls.MCL_BLS12_381});
    std.debug.print(" {}\n", .{bls.MCLBN_COMPILED_TIME_VAR});
    const res = bls.blsInit(bls.MCL_BLS12_381, bls.MCLBN_COMPILED_TIME_VAR);
    if (res != 0) {
        std.debug.print("{}\n", .{res});
        @panic("blsInit failed");
    }
}
test "test init" {
    init();
}
