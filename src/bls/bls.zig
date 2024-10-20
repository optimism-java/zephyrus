const BLS = struct {
    const curves = enum {
        bls_c256,
        bls_c384,
        bls_c384_256,
    };

    fn blsLibrary() type {
        return struct {
            pub usingnamespace @cImport({
                @cDefine("BLS_ETH", "1");
                @cInclude("bls/bls384_256.h");
                @cInclude("bls/bls.h");
            });
        };
    }
    const bls = blsLibrary();

    const ID_SIZE = 32;
    const SECRETKEY_SIZE = 32;
    const PUBLICKEY_SIZE = 64;
    const SIGNATURE_SIZE = 32;

    pub fn init() void {
        if (bls.blsInit(bls.MCL_BLS12_381, bls.MCLBN_COMPILED_TIME_VAR) != 0) @panic("BLS library mismatch");
    }
};

test "test init" {
    BLS.init();
}
