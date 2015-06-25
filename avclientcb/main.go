// Copyright 2013 the Go ClamAV authors
// Use of this source code is governed by a
// license that can be found in the LICENSE file.

// This is an implementation of a client for the ClamAV library which uses the callback mechanism
// of ClamAV to scan files for viruses. The code here will accept files and
// directories as arguments and will crawl them (recursively) scanning every file. This code will
// not follow symlinks but will also not make an effort to stay on the same computer. If you have
// remote mounted filesystems this code will scan all files available on them.
package main

// The code will spawn 8 scanners on 2 OS threads by default but uses only one ClamAV engine. You
// can control that via the -cpus and -workers flags. The memory footprint is around 200 MB with
// default virus databases downloaded from http://www.clamav.net, CPU usage is ~80% of one CPU.
//
// The code has been tested on Linux and OSX

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
)

import "github.com/mirtchovski/clamav"

var debug = flag.Bool("debug", false, "enable debugging output")
var clamavdebug = flag.Bool("clamavdebug", false, "enable debugging output from the ClamAV engine")
var clamavversion = flag.Bool("clamavversion", false, "print out the version of ClamAV linked")
var scan = flag.Bool("scan", true, "don't scan files for viruses, only walk directories")
var workers = flag.Int("workers", 8, "number of scanning workers")
var cpus = flag.Int("cpus", 2, "number of active OS threads")
var db = flag.String("db", clamav.DBDir(), "virus definition database")
var testmap = flag.Bool("testfmap", false, "test memory scanning only")

var eicar = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s path [...]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

// A counter goroutine sits between the walker and the workers and keeps track
// of the walker's progress.
func counter(cnt, out chan string) {
	c := uint64(0)
	for path := range cnt {
		c++
		if c%1000 == 0 {
			log.Printf("scanned %d so far, now scanning %s", c, path)
		}
		out <- path
	}
	log.Printf("total submitted for scan: %d", c)
	close(out)
}

// Workers receive file names on 'in', scan them, and output the results on 'out'
func worker(in, cnt chan string, done chan bool, engine *clamav.Engine) {
	for path := range in {
		if *debug {
			log.Printf("scanning %s", path)
		}
		if *scan {
			virus, _, err := engine.ScanFileCb(path, clamav.ScanStdopt|clamav.ScanAllmatches, path)
			if virus != "" {
				log.Printf("virus found in %s: %s", path, virus)
			} else if err != nil {
				log.Printf("error scanning %s: %v", path, err)
			}
		}
	}
	done <- true
}

// Walker visits every file inside path, recursing into subdirectories
// and sending all filenames it encounters on "in"
func walker(path string, in chan string) {
	if *debug {
		log.Printf("examining %s", path)
	}
	// When encountering a symlink to a directory Lstat will return false for IsDir, but Stat will
	// return true.
	lfi, err := os.Lstat(path)
	if err != nil {
		log.Printf("%v", err)
		return
	}
	if lfi.IsDir() {
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		for _, v := range dir {
			walker(path+"/"+v.Name(), in)
		}
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		log.Printf("%v", err)
		return
	}
	if fi.IsDir() {
		return
	}
	in <- path
}

func PreCacheCb(fd int, ftype string, context interface{}) clamav.ErrorCode {
	if *debug {
		log.Printf("pre cache callback for %s: fd=%d ftype=%s", context, fd, ftype)
	}

	return clamav.Clean
}

func PreScanCb(fd int, ftype string, context interface{}) clamav.ErrorCode {
	if *debug {
		log.Printf("pre scan callback for %s: fd=%d ftype=%s", context, fd, ftype)
	}

	return clamav.Clean
}

func PostScanCb(fd int, result clamav.ErrorCode, virname string, context interface{}) clamav.ErrorCode {
	if *debug {
		log.Printf("post scan callback for %s: fd=%d result=%s virus=%s", context, fd, clamav.StrError(result), virname)
	}

	return clamav.Clean
}

func HashCb(fd int, size uint64, md5 []byte, virname string, context interface{}) {
	if *debug {
		log.Printf("hash callback for %s: fd=%d size=%d md5=%s virus=%s", context, fd, size, md5, virname)
	}

	return
}

func initClamAV() *clamav.Engine {
	clamav.Init(clamav.InitDefault)
	engine := clamav.New()
	sigs, err := engine.Load(*db, clamav.DbStdopt)
	if err != nil {
		log.Fatalf("can not initialize ClamAV engine: %v", err)
	}
	if *debug {
		log.Printf("loaded %d signatures", sigs)
	}

	engine.SetPreCacheCallback(PreCacheCb)
	engine.SetPreScanCallback(PreScanCb)
	engine.SetPostScanCallback(PostScanCb)
	engine.SetHashCallback(HashCb)

	engine.Compile()

	return engine
}

func main() {
	var engine *clamav.Engine

	flag.Usage = usage
	flag.Parse()

	if *clamavversion {
		fmt.Println(clamav.Retver())
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) == 0 && !*testmap {
		fmt.Fprintln(os.Stderr, "error: missing path\n")
		usage()
	}

	runtime.GOMAXPROCS(*cpus)

	if *scan {
		log.Println("initializing ClamAV database...")
		engine = initClamAV()
	}

	if *testmap {
		fmap := clamav.OpenMemory(eicar)
		defer clamav.CloseMemory(fmap)

		virus, _, err := engine.ScanMapCb(fmap, clamav.ScanStdopt|clamav.ScanAllmatches, "eicar memorytest")
		if err != nil {
			log.Printf("error scanning in-memory: %v\n", err)
		}
		log.Printf("in-memory scan result: %s (eicar)\n", virus)
		return
	}

	in := make(chan string, 1024)
	cnt := make(chan string, 1024)
	out := make(chan string, 1024)
	done := make(chan bool, *workers)

	log.Println("scan starting...")

	if *clamavdebug {
		clamav.Debug()
	}

	for i := 0; i < *workers; i++ {
		go worker(cnt, out, done, engine)
	}

	go counter(in, cnt)

	for _, v := range args {
		walker(v, in)
	}

	close(in)
	for i := 0; i < *workers; i++ {
		<-done
	}

	log.Println("scan completed...")
}
