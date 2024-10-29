check_nasm:
	@if [ "$(shell uname)" = "Linux" ]; then \
		if ! command -v nasm > /dev/null; then \
			echo "Installing nasm..." && \
			sudo apt-get update && \
			sudo apt-get install -y nasm; \
		else \
			echo "nasm is already installed"; \
		fi \
	fi

SPEC_VERSION ?= v1.5.0-alpha.8

# Update deps target to include nasm check
deps: check_nasm
	@echo "Installing dependencies"
	@git submodule update --init --recursive
	@cd bls && make -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib

	mkdir -p consensus-spec-tests
	wget https://github.com/ethereum/consensus-spec-tests/releases/download/$(SPEC_VERSION)/general.tar.gz -O - | tar -xz -C consensus-spec-tests
	wget https://github.com/ethereum/consensus-spec-tests/releases/download/$(SPEC_VERSION)/minimal.tar.gz -O - | tar -xz -C consensus-spec-tests
	wget https://github.com/ethereum/consensus-spec-tests/releases/download/$(SPEC_VERSION)/mainnet.tar.gz -O - | tar -xz -C consensus-spec-tests
