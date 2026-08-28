.PHONY: all release native clean

all: release

release: opm.odin
	odin build opm.odin -file -o:speed -lto:thin -out:opm

native: opm.odin
	odin build opm.odin -file -o:speed -lto:thin -microarch:native -out:opm

clean:
	rm -f opm
