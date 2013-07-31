clamav
======

Go bindings for the ClamAV antivirus library (http://clamav.net)

This is a thin wrapper around the ClamAV antivirus library. The code includes a small scanner as an
example in the avclient directory. 

To learn more about ClamAV and to install antivirus databases see http://www.clamav.net/lang/en/.

To build make sure the C compiler can see the libclamav shared library, if not you may have to
specify it as `LDFLAGS: -L/path/to/dylib` in the CGo header of each file importing "C". Alternatively, if you
have compiled ClamAV in a non-standard directory you can use the following arguments to the go tool:

    CGO_CFLAGS=-I/path/to/include CGO_LDFLAGS=-L/path/to/lib go install

For example, on Mountain Lion, after compiling ClamAV by hand, the library gets installed in 
`/usr/local/lib/x86_64`. The following command then works to compile the wrappers:

	CGO_CFLAGS=-I/usr/local/include CGO_LDFLAGS=-L/usr/local/lib/x86_64 go install

Run `go build` and, if you have copied the virus files from ClamAV's test/ subdirectory, you can 
run `go test`. Run `go test -test.bench=Bench` to run the benchmarks.

The avclient directory contains a simple filesystem scanner. To compile it run `go build` in that
directory.
