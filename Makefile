.PHONY: all release native clean

all: release

release:
	cargo build --release
	cp target/release/opm opm

native:
	RUSTFLAGS="-C target-cpu=native" cargo build --release
	cp target/release/opm opm

clean:
	cargo clean
	rm -f opm
