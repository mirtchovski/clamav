clamav
======

Go bindings for the ClamAV antivirus library (http://clamav.net)

This is a thin wrapper around the ClamAV antivirus library. The code includes a small scanner as an
example in the avclient directory. 

To learn more about ClamAV and to install antivirus databases see http://www.clamav.net/lang/en/.

To build make sure the C compiler can see the libclamav shared library, if not you may have to
specify it as -L/path/to/dylib in the CGo header of each file importing "C". Run "go build" and, if
you have copied the virus files from ClamAV's test/ subdirectory, you can run "go test". Run "go test
-test.bench Bench" to run the benchmarks.

The avclient directory contains a simple filesystem scanner. To compile it run "go build" in that
directory.
