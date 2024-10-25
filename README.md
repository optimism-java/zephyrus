# zephyrus

## Build

```bash
git clone --recursive https://github.com/optimism-java/zephyrus.git
cd zephyrus
git submodule update --init --recursive
cd bls
make -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib
zig build
```