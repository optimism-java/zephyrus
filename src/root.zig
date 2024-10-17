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
pub const epoch_helper = @import("consensus/helpers/epoch.zig");
pub const attestation_helper = @import("consensus/helpers/attestation.zig");
pub const weak_subjectivity_helper = @import("consensus/helpers/weak_subjectivity.zig");
pub const validator_helper = @import("consensus/helpers/validator.zig");
pub const domain_helper = @import("consensus/helpers/domain.zig");
pub const signing_root_helper = @import("consensus/helpers/signing_root.zig");
pub const block_root_helper = @import("consensus/helpers/block_root.zig");
pub const seed_helper = @import("consensus/helpers/seed.zig");
pub const committee_helper = @import("consensus/helpers/committee.zig");
pub const shuffle_helper = @import("consensus/helpers/shuffle.zig");
pub const balance_helper = @import("consensus/helpers/balance.zig");
pub const ssz = @import("./ssz/ssz.zig");
pub const snappy = @import("./snappy/snappy.zig");
pub const merkle = @import("consensus/helpers/merkle.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
    _ = @import("./spec_tests/root.zig");
}
