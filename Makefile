.PHONY: build test run clean install

BINARY_NAME=vault-airlock
KDBX_PATH?=test.kdbx
SOCKET_PATH?=/tmp/kdbx.sock

build:
	cargo build --release

test:
	cargo test

run: build
	./target/release/$(BINARY_NAME) serve -k $(KDBX_PATH) -s $(SOCKET_PATH)

clean:
	cargo clean
	rm -f $(SOCKET_PATH)

install: build
	install -Dm755 target/release/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
