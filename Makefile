.PHONY: all release native clean

all: release

release: src/*.odin
	odin build src -o:speed -out:opm

native: src/*.odin
	odin build src -o:speed -lto:thin -microarch:native -out:opm

clean:
	rm -f opm
