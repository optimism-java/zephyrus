const bls = @cImport({
    @cDefine("BLS_ETH", "");
    @cInclude("mcl/bn_c384_256.h");
    @cInclude("bls/bls.h");
});

pub fn init() void {
    if (bls.blsInit(bls.MCL_BLS12_381, bls.MCLBN_COMPILED_TIME_VAR) != 0) @panic("BLS library mismatch");
}