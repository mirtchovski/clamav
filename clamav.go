// Copyright 2013 the Go ClamAV authors
// Use of this source code is governed by a
// license that can be found in the LICENSE file.

// Clamav is a wrapper around libclamav.
// For more information about libclamav see http://www.clamav.net
package clamav

/*
#include <clamav.h>
#include <stdlib.h>
#cgo LDFLAGS:-lclamav
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func init() {
	err := Init()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	return
}

// Init initializes the ClamAV library
func Init() error {
	err := ErrorCode(C.cl_init(C.uint(InitDefault)))
	if err != Success {
		return fmt.Errorf("Init: %v", StrError(err))
	}
	return nil
}

// New allocates a new ClamAV engine.
func New() *Engine {
	eng := (*Engine)(C.cl_engine_new())
	return eng
}

// Free relleases the memory associated with ClamAV. Since the ClamAV
// engine can consume several megabytes of memory which is not visible
// by the Go garbage collector, Free should be called when the engine is no
// longer in use.
func (e *Engine) Free() int {
	return int(C.cl_engine_free((*C.struct_cl_engine)(e)))
}

// SetNum sets a number in the specified field of the engine configuration.
// Certain fields accept only 32-bit numbers, silently truncating the higher bits
// of the engine config. See dat.go for more information.
func (e *Engine) SetNum(field EngineField, num uint64) error {
	err := C.cl_engine_set_num((*C.struct_cl_engine)(e), C.enum_cl_engine_field(field), C.longlong(num))
	if ErrorCode(err) != Success {
		return fmt.Errorf("%v", StrError(ErrorCode(err)))
	}
	return nil
}

// GetNum acquires a number from the specified field of the engine configuration. Tests show that
// the ClamAV library will not overflow 32-bit fields, so a GetNum on a 32-bit field can safely be
// cast to uint32.
func (e *Engine) GetNum(field EngineField) (uint64, error) {
	var err ErrorCode
	ne := (*C.struct_cl_engine)(e)
	num := uint64(C.cl_engine_get_num(ne, C.enum_cl_engine_field(field), (*C.int)(unsafe.Pointer(&err))))
	if err != Success {
		return num, fmt.Errorf("%v", StrError(ErrorCode(err)))
	}
	return num, nil
}

// SetString sets a string in the corresponding field of the engine configuration.
// See dat.go for the corresponding (char *) fields in ClamAV.
func (e *Engine) SetString(field EngineField, s string) error {
	str := C.CString(s)
	defer C.free(unsafe.Pointer(str))

	err := C.cl_engine_set_str((*C.struct_cl_engine)(e), C.enum_cl_engine_field(field), str)
	if ErrorCode(err) != Success {
		return fmt.Errorf("%v", StrError(ErrorCode(err)))
	}
	return nil
}

// GetString returns a string from the corresponding field of the engine configuration.
func (e *Engine) GetString(field EngineField) (string, error) {
	var err ErrorCode

	str := C.GoString(C.cl_engine_get_str((*C.struct_cl_engine)(e), C.enum_cl_engine_field(field), (*C.int)(unsafe.Pointer(&err))))
	if err != Success {
		return "", fmt.Errorf("%v", StrError(ErrorCode(err)))
	}
	return str, nil
}

func (e *Engine) CopySettings() *Settings {
	return (*Settings)(C.cl_engine_settings_copy((*C.struct_cl_engine)(e)))
}

func (e *Engine) ApplySettings(s *Settings) error {
	err := ErrorCode(C.cl_engine_settings_apply((*C.struct_cl_engine)(e), (*C.struct_cl_settings)(s)))
	if err != Success {
		return fmt.Errorf("%v", StrError(err))
	}
	return nil
}

func FreeSettings(s *Settings) error {
	err := ErrorCode(C.cl_engine_settings_free((*C.struct_cl_settings)(s)))
	if err != Success {
		return fmt.Errorf("%v", StrError(err))
	}
	return nil
}

func (e *Engine) Compile() error {
	err := ErrorCode(C.cl_engine_compile((*C.struct_cl_engine)(e)))
	if err != Success {
		return fmt.Errorf("%v", StrError(err))
	}
	return nil
}
func (e *Engine) Addref() error {
	err := ErrorCode(C.cl_engine_compile((*C.struct_cl_engine)(e)))
	if err != Success {
		return fmt.Errorf("%v", StrError(err))
	}
	return nil
}

func (e *Engine) ScanDesc(desc int, opts uint) (string, uint, error) {
	var name *C.char
	var scanned C.ulong
	err := ErrorCode(C.cl_scandesc(C.int(desc), &name, &scanned, (*C.struct_cl_engine)(e), C.uint(opts)))
	if err == Success {
		return "", 0, nil
	}
	if err == Virus {
		return C.GoString(name), uint(scanned), fmt.Errorf(StrError(err))
	}
	return "", 0, fmt.Errorf(StrError(err))
}

// ScanFile scans a single file for viruses using the ClamAV databases. It returns the virus name
// (if found), the number of bytes read from the file, in CountPrecision units, and a status code.
// If the file is clean the error code will be Success (Clean) and virus name will be empty. If a
// virus is found the error code will be the corresponding string for Virus (currently "Virus(es)
// detected").
func (e *Engine) ScanFile(path string, opts uint) (string, uint, error) {
	var name *C.char
	var scanned C.ulong
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	err := ErrorCode(C.cl_scanfile(cpath, &name, &scanned, (*C.struct_cl_engine)(e), C.uint(opts)))
	if err == Success {
		return "", 0, nil
	}
	if err == Virus {
		return C.GoString(name), uint(scanned), fmt.Errorf(StrError(err))
	}
	return "", 0, fmt.Errorf(StrError(err))
}

// LoadDB loads a single database file or all databases depending on whether its first argument
// (path) points to a file or a directory. A number of loaded signatures will be added to signo
// (the virus counter should be initialized to zero initially)
func (e *Engine) Load(path string, dbopts uint) (uint, error) {
	var signo uint
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	err := ErrorCode(C.cl_load(cpath, (*C.struct_cl_engine)(e), (*C.uint)(unsafe.Pointer(&signo)), C.uint(dbopts)))
	if err != Success {
		return 0, fmt.Errorf("Load: %v", StrError(err))
	}
	return signo, nil
}

// DBDir returns the directory where the virus database is located
func DBDir() string {
	return C.GoString(C.cl_retdbdir())
}

// StatIniDir initializes the Stat structure so the internal state of the database
// can be checked for errors stat should not be reused across calls to Stat*
func StatIniDir(dir string, stat *Stat) error {
	p := C.CString(dir)
	defer C.free(unsafe.Pointer(p))
	err := ErrorCode(C.cl_statinidir(p, (*C.struct_cl_stat)(stat)))
	if err != Success {
		return fmt.Errorf("StatIniDir: %v", StrError(err))
	}
	return nil
}

// StatChkDir returns 0 if no change to the directory pointed to by the Stat structure
// occurred, or 1 if some change occurred.
func StatChkDir(stat *Stat) bool {
	t := C.cl_statchkdir((*C.struct_cl_stat)(stat))
	if t == 1 {
		return true
	}
	return false
}

func StatFree(stat *Stat) error {
	err := ErrorCode(C.cl_statfree((*C.struct_cl_stat)(stat)))
	if err != Success {
		return fmt.Errorf("StatFree: %v", StrError(err))
	}
	return nil
}

// StatChkReload updates the internal state of the database if a change in the path
// referenced by stat occurred
func StatChkReload(stat *Stat) (bool, error) {
	if StatChkDir(stat) {
		StatFree(stat)
		stat = new(Stat)
		return true, StatIniDir(DBDir(), stat)
	}
	return false, nil
}

// CountSigs counts the number of signatures that can be loaded from
// the directory in path.
func CountSigs(path string, options uint) (uint, error) {
	var cnt uint

	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	err := ErrorCode(C.cl_countsigs(p, C.uint(options), (*C.uint)(unsafe.Pointer(&cnt))))
	if err != Success {
		return 0, fmt.Errorf("CountSigs: %v", StrError(err))
	}
	return cnt, nil
}

// Debug enables debug messages from libclamav
func Debug() {
	C.cl_debug()
}

func Retflevel() uint {
	return uint(C.cl_retflevel())
}

func Retver() string {
	return C.GoString(C.cl_retver())
}

// Strerror converts LibClam error codes to human readable format
func StrError(errno ErrorCode) string {
	return C.GoString(C.cl_strerror(C.int(errno)))
}
