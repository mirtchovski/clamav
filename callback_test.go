// Copyright 2013 the Go ClamAV authors
// Use of this source code is governed by a
// license that can be found in the LICENSE file.

package clamav

import (
	"testing"
)

var eicar = []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

func TestFmapOpenMemory(t *testing.T) {
	fmap := FmapOpenMemory(eicar)
	if fmap == nil {
		t.Fatalf("FmapOpenMemory failed")
	}

	fmap.Close()
}

func TestScanMap(t *testing.T) {
	eicarvirname := "Eicar-Test-Signature"

	eng, err := testInitAll()
	if err != nil {
		t.Fatalf("testInitAll: %v")
	}
	defer eng.Free()

	fmap := FmapOpenMemory(eicar)
	if fmap == nil {
		t.Fatalf("FmapOpenMemory failed")
	}
	defer fmap.Close()

	virus, scan, err := eng.ScanMap(fmap, ScanStdopt, nil)
	if err != nil {
		if virus != "" {
			if virus != eicarvirname {
				t.Errorf("scanmap: eicar: virus = %s (want %s); scanned: %d %v", virus, eicarvirname, scan, err)
			}
		}
	}
}

func TestFmapClose(t *testing.T) {
	fmap := FmapOpenMemory(eicar)
	if fmap == nil {
		t.Fatalf("FmapOpenMemory failed")
	}
	fmap.Close()
}
