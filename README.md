# zephyrus

This repo is development with zig, zig is a coding language for more [info](https://ziglang.org/) for basic coding [guide](https://zig.guide/standard-library/readers-and-writers)

The current version being used in development is `0.14.0-dev.2079+ba2d00663`. You may use [`zigup`](https://github.com/marler8997/zigup) to download and use this specific version.

## Build

```bash
git clone --recursive https://github.com/optimism-java/zephyrus.git
cd zephyrus
git submodule update --init --recursive
cd bls
make -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib
zig build
```

## Test

first you should build bls as described above

when you run `zig build test`, the spec tests are not run by default.

if you want to run spec tests, you need to download the test vectors and add `-Dspec=true` to the zig build command.

```bash
# download test vectors
make deps_test
# add -Dspec=true to run spec tests
zig build test -Dspec=true
```
