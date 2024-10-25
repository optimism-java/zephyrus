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

# Update deps target to include nasm check
deps: check_nasm
	@echo "Installing dependencies"
	@git submodule update --init --recursive
	@cd bls && make -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib
