pub const configs = @import("configs/config.zig");
pub const preset = @import("presets/preset.zig");
pub const types = @import("primitives/types.zig");
pub const constants = @import("primitives/constants.zig");
pub const utils = @import("primitives/utils.zig");
pub const consensus = @import("consensus/types.zig");
pub const phase0 = @import("consensus/phase0/types.zig");
pub const altair = @import("consensus/altair/types.zig");
pub const bellatrix = @import("consensus/bellatrix/types.zig");
pub const capella = @import("consensus/capella/types.zig");
pub const deneb = @import("consensus/deneb/types.zig");
pub const electra = @import("consensus/electra/types.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
