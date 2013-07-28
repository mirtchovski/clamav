// Copyright 2013 the Go ClamAV authors
// Use of this source code is governed by a
// license that can be found in the LICENSE file.

package clamav

// Data and consts for ClamAV wrapper

/*
#include <clamav.h>
#include <stdlib.h>
*/
import "C"

type Engine C.struct_cl_engine
type Settings C.struct_cl_settings

type ErrorCode C.cl_error_t

const CountPrecision = C.CL_COUNT_PRECISION

// return codes
const Clean = C.CL_SUCCESS
const (
	Success   ErrorCode = C.CL_SUCCESS
	Virus               = C.CL_VIRUS
	Enullarg            = C.CL_ENULLARG
	Earg                = C.CL_EARG
	Emalfdb             = C.CL_EMALFDB
	Ecvd                = C.CL_ECVD
	Everify             = C.CL_EVERIFY
	Eunpack             = C.CL_EUNPACK
	Eopen               = C.CL_EOPEN // IO and memory errors below
	Ecreat              = C.CL_ECREAT
	Eunlink             = C.CL_EUNLINK
	Estat               = C.CL_ESTAT
	Eread               = C.CL_EREAD
	Eseek               = C.CL_ESEEK
	Ewrite              = C.CL_EWRITE
	Edup                = C.CL_EDUP
	Eacces              = C.CL_EACCES
	Etmpfile            = C.CL_ETMPFILE
	Etmpdir             = C.CL_ETMPDIR
	Emap                = C.CL_EMAP
	Emem                = C.CL_EMEM
	Etimeout            = C.CL_ETIMEOUT
	Break               = C.CL_BREAK // internal (not reported outside libclamav)
	Emaxrec             = C.CL_EMAXREC
	Emaxsize            = C.CL_EMAXSIZE
	Emaxfiles           = C.CL_EMAXFILES
	Eformat             = C.CL_EFORMAT
	//	Eparse                      = C.CL_EPARSE	// 0.98 adds this
	Ebytecode         = C.CL_EBYTECODE
	EbytecodeTestfail = C.CL_EBYTECODE_TESTFAIL
	Elock             = C.CL_ELOCK // c4w error codes
	Ebusy             = C.CL_EBUSY
	Estate            = C.CL_ESTATE
	ELast             = C.CL_ELAST_ERROR // no error codes below this line please
)

type EngineField C.enum_cl_engine_field

const (
	EngineMaxScansize      EngineField = C.CL_ENGINE_MAX_SCANSIZE      // uint64_t
	EngineMaxFilesize                  = C.CL_ENGINE_MAX_FILESIZE      // uint64_t
	EngineMaxRecursion                 = C.CL_ENGINE_MAX_RECURSION     // uint32_t
	EngineMaxFiles                     = C.CL_ENGINE_MAX_FILES         // uint32_t
	EngineMinCcCount                   = C.CL_ENGINE_MIN_CC_COUNT      // uint32_t
	EngineMinSsnCount                  = C.CL_ENGINE_MIN_SSN_COUNT     // uint32_t
	EnginePuaCategories                = C.CL_ENGINE_PUA_CATEGORIES    // (char *)
	EngineDbOptions                    = C.CL_ENGINE_DB_OPTIONS        // uint32_t
	EngineDbVersion                    = C.CL_ENGINE_DB_VERSION        // uint32_t
	EngineDbTime                       = C.CL_ENGINE_DB_TIME           // time_t
	EngineAcOnly                       = C.CL_ENGINE_AC_ONLY           // uint32_t
	EngineAcMindepth                   = C.CL_ENGINE_AC_MINDEPTH       // uint32_t
	EngineAcMaxdepth                   = C.CL_ENGINE_AC_MAXDEPTH       // uint32_t
	EngineTmpdir                       = C.CL_ENGINE_TMPDIR            // (char *)
	EngineKeeptmp                      = C.CL_ENGINE_KEEPTMP           // uint32_t
	EngineBytecodeSecurity             = C.CL_ENGINE_BYTECODE_SECURITY // uint32_t
	EngineBytecodeTimeout              = C.CL_ENGINE_BYTECODE_TIMEOUT  // uint32_t
	EngineBytecodeMode                 = C.CL_ENGINE_BYTECODE_MODE     // uint32_t
)

type BytecodeSecurity C.enum_bytecode_security

const (
	BytecodeTrustAll     BytecodeSecurity = C.CL_BYTECODE_TRUST_ALL     // obsolete
	BytecodeTrustSigned                   = C.CL_BYTECODE_TRUST_SIGNED  // default
	BytecodeTrustNothing                  = C.CL_BYTECODE_TRUST_NOTHING // paranoid setting
)

type BytecodeMode C.enum_bytecode_mode

const (
	BytecodeModeAuto        BytecodeMode = C.CL_BYTECODE_MODE_AUTO        // JIT if possible, fallback to interpreter
	BytecodeModeJit                      = C.CL_BYTECODE_MODE_JIT         // force JIT
	BytecodeModeInterpreter              = C.CL_BYTECODE_MODE_INTERPRETER // force interpreter
	BytecodeModeTest                     = C.CL_BYTECODE_MODE_TEST        // both JIT and interpreter, compare results, all failures are fatal
	BytecodeModeOff                      = C.CL_BYTECODE_MODE_OFF         // for query only, not settable
)

// db options
const (
	DbPhishing         = 0x2
	DbPhishingUrls     = 0x8
	DbPua              = 0x10
	DbCvdnotmp         = 0x20 // obsolete
	DbOfficial         = 0x40 // internal
	DbPuaMode          = 0x80
	DbPuaInclude       = 0x100
	DbPuaExclude       = 0x200
	DbCompiled         = 0x400 // internal
	DbDirectory        = 0x800 // internal
	DbOfficialOnly     = 0x1000
	DbBytecode         = 0x2000
	DbSigned           = 0x4000 // internal
	DbBytecodeUnsigned = 0x8000

	// recommended db settings
	DbStdopt = (DbPhishing | DbPhishingUrls | DbBytecode)
)

const (
	// scan options
	ScanRaw                   = 0x0
	ScanArchive               = 0x1
	ScanMail                  = 0x2
	ScanOle2                  = 0x4
	ScanBlockencrypted        = 0x8
	ScanHtml                  = 0x10
	ScanPe                    = 0x20
	ScanBlockbroken           = 0x40
	ScanMailurl               = 0x80  // ignored
	ScanBlockmax              = 0x100 // ignored
	ScanAlgorithmic           = 0x200
	ScanPhishingBlockSSL      = 0x800 // ssl mismatches, not ssl by itself
	ScanPhishingBlockCloak    = 0x1000
	ScanElf                   = 0x2000
	ScanPdf                   = 0x4000
	ScanStructured            = 0x8000
	ScanStructuredSSNNormal   = 0x10000
	ScanStructuredSSNStripped = 0x20000
	ScanPartialMessage        = 0x40000
	ScanHeuristicPrecedence   = 0x80000
	ScanBlockmacros           = 0x100000
	ScanAllmatches            = 0x200000

	ScanInternalCollectSHA = 0x80000000 // Enables hash output in sha-collect builds - for internal use only

	// recommended scan settings
	ScanStdopt = (ScanArchive | ScanMail | ScanOle2 | ScanPdf | ScanHtml | ScanPe | ScanAlgorithmic | ScanElf)
)

// cl_countsigs options
const (
	CountSigsOfficial = iota
	CountSigsUnofficial
	CountSigsAll = (CountSigsOfficial | CountSigsUnofficial)
)

type Stat C.struct_cl_stat
type Cvd C.struct_cl_cvd

const InitDefault = 0
