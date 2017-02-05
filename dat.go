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

// Engine is a ClamAV virus scanning engine
type Engine C.struct_cl_engine

// Settings models the settings applied to a ClamAV engine
type Settings C.struct_cl_settings

// ErrorCode models ClamAV errors
type ErrorCode C.cl_error_t

// return codes
const (
	Success           ErrorCode = C.CL_SUCCESS
	Clean                       = C.CL_CLEAN
	Virus                       = C.CL_VIRUS
	Enullarg                    = C.CL_ENULLARG
	Earg                        = C.CL_EARG
	Emalfdb                     = C.CL_EMALFDB
	Ecvd                        = C.CL_ECVD
	Everify                     = C.CL_EVERIFY
	Eunpack                     = C.CL_EUNPACK
	Eopen                       = C.CL_EOPEN // IO and memory errors below
	Ecreat                      = C.CL_ECREAT
	Eunlink                     = C.CL_EUNLINK
	Estat                       = C.CL_ESTAT
	Eread                       = C.CL_EREAD
	Eseek                       = C.CL_ESEEK
	Ewrite                      = C.CL_EWRITE
	Edup                        = C.CL_EDUP
	Eacces                      = C.CL_EACCES
	Etmpfile                    = C.CL_ETMPFILE
	Etmpdir                     = C.CL_ETMPDIR
	Emap                        = C.CL_EMAP
	Emem                        = C.CL_EMEM
	Etimeout                    = C.CL_ETIMEOUT
	Break                       = C.CL_BREAK // internal (not reported outside libclamav)
	Emaxrec                     = C.CL_EMAXREC
	Emaxsize                    = C.CL_EMAXSIZE
	Emaxfiles                   = C.CL_EMAXFILES
	Eformat                     = C.CL_EFORMAT
	Eparse                      = C.CL_EPARSE
	Ebytecode                   = C.CL_EBYTECODE
	EbytecodeTestfail           = C.CL_EBYTECODE_TESTFAIL
	Elock                       = C.CL_ELOCK // c4w error codes
	Ebusy                       = C.CL_EBUSY
	Estate                      = C.CL_ESTATE
	ELast                       = C.CL_ELAST_ERROR // no error codes below this line please
)

// EngineField selects a particular engine settings field
type EngineField C.enum_cl_engine_field

// Engine settings
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

// BytecodeSecurity models security settings for the bytecode scanner
type BytecodeSecurity C.enum_bytecode_security

// Bytecode security settings
const (
	BytecodeTrustAll     BytecodeSecurity = C.CL_BYTECODE_TRUST_ALL     // obsolete
	BytecodeTrustSigned                   = C.CL_BYTECODE_TRUST_SIGNED  // default
	BytecodeTrustNothing                  = C.CL_BYTECODE_TRUST_NOTHING // paranoid setting
)

// BytecodeMode selects mode for the bytecode scanner
type BytecodeMode C.enum_bytecode_mode

// Bytecode mode settings
const (
	BytecodeModeAuto        BytecodeMode = C.CL_BYTECODE_MODE_AUTO        // JIT if possible, fallback to interpreter
	BytecodeModeJit                      = C.CL_BYTECODE_MODE_JIT         // force JIT
	BytecodeModeInterpreter              = C.CL_BYTECODE_MODE_INTERPRETER // force interpreter
	BytecodeModeTest                     = C.CL_BYTECODE_MODE_TEST        // both JIT and interpreter, compare results, all failures are fatal
	BytecodeModeOff                      = C.CL_BYTECODE_MODE_OFF         // for query only, not settable
)

// Virus signature database options
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

// Scanner options
const (
	// scan options
	ScanRaw                   = 0x0
	ScanArchive               = 0x1
	ScanMail                  = 0x2
	ScanOle2                  = 0x4
	ScanBlockencrypted        = 0x8
	ScanHTML                  = 0x10
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
	ScanSwf                   = 0x400000
	ScanPartitionIntxn        = 0x800000

	ScanCollectPerformanceInfo = 0x40000000

	// recommended scan settings
	ScanStdopt = (ScanArchive | ScanMail | ScanOle2 | ScanPdf | ScanHTML | ScanPe | ScanAlgorithmic | ScanElf | ScanSwf)
)

// Signature count options
const (
	CountSigsOfficial = iota
	CountSigsUnofficial
	CountSigsAll = (CountSigsOfficial | CountSigsUnofficial)
)

// Engine options
const (
	// engine options
	EngineOptionsNone = iota
	EngineOptionsDisableCache
	EngineOptionsForceToDisk
	EngineOptionsDisablePEStats
)

// Engine fields
const (
	MaxScansize           = iota // uint64
	MaxFilesize                  // uint64
	MaxRecursion                 // uint32
	MaxFiles                     // uint32
	MinCCCount                   // uint32
	MinSSNCount                  // uint32
	PuaCategories                // string
	DbOptions                    // uint32
	DbVersion                    // uint32
	DbTime                       // time
	AcOnly                       // uint32
	AcMindepth                   // uint32
	AcMaxdepth                   // uint32
	Tmpdir                       // string
	Keeptmp                      // uint32
	BytecodeSecurityField        // uint32
	BytecodeTimeout              // uint32
	BytecodeModeField            // uint32
	MaxEmbeddedpe                // uint64
	MaxHtmlnormalize             // uint64
	MaxHtmlnotags                // uint64
	MaxScriptnormalize           // uint64
	MaxZiptypercg                // uint64
	Forcetodisk                  // uint32
	DisableCache                 // uint32
	DisablePEStats               // uint32
	StatsTimeout                 // uint32
	MaxPartitions                // uint32
	MaxIconspe                   // uint32

)

// Stat holds engine statistics
type Stat C.struct_cl_stat

// Cvd models an engine virus database
type Cvd C.struct_cl_cvd

// Fmap models in-memory files
type Fmap C.cl_fmap_t

// InitDefault has default initialization settings
const InitDefault = 0

// CallbackPreCache is called for each processed file (both the entry level - AKA 'outer' - file and
// inner files - those generated when processing archive and container files), before
// the actual scanning takes place.
//
// Input:
// fd      = File descriptor which is about to be scanned
// type    = File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE")
// context = Opaque application provided data
//
// Output:
// Clean = File is scanned
// Break = Whitelisted by callback - file is skipped and marked as Clean
// Virus = Blacklisted by callback - file is skipped and marked as Virus
type CallbackPreCache func(fd int, ftype string, context interface{}) ErrorCode

// CallbackPreScan is called for each NEW file (inner and outer) before the scanning takes place. This is
// roughly the the same as CallbackPreCache, but it is affected by clean file caching.
// This means that it won't be called if a clean cached file (inner or outer) is
// scanned a second time.
//
// Input:
// fd      = File descriptor which is about to be scanned
// type    = File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE")
// context = Opaque application provided data
//
// Output:
// Clean = File is scanned
// Break = Whitelisted by callback - file is skipped and marked as Clean
// Virus = Blacklisted by callback - file is skipped and marked as Virus
type CallbackPreScan func(fd int, ftype string, context interface{}) ErrorCode

// CallbackPostScan is called for each processed file (inner and outer), after the scanning is complete.
//
// Input:
// fd      = File descriptor which is was scanned
// result  = The scan result for the file
// virname = Virus name if infected
// context = Opaque application provided data
//
// Output:
// Clean = Scan result is not overridden
// Break = Whitelisted by callback - scan result is set to Clean
// Virus = Blacklisted by callback - scan result is set to Virus
type CallbackPostScan func(fd int, result ErrorCode, virname string, context interface{}) ErrorCode

// CallbackSigLoad is called whenever a new signature has been loaded
//
// The function signature is:
// type = The signature type (e.g. "db", "ndb", "mdb", etc.)
// name = The virus name
// custom = The signature is official (custom == 0) or custom (custom != 0)
// context = Opaque application provided data
//
// Output:
// 0     = Load the current signature
// Non 0 = Skip the current signature
//
// WARNING: Some signatures (notably ldb, cbc) can be dependent upon other signatures.
//          Failure to preserve dependency chains will result in database loading failure.
//          It is the implementor's responsibility to guarantee consistency.
// type CallbackSigLoad C.clcb_sigload

// Msg selects the logging severity for an engine
type Msg C.enum_cl_msg

// Logging severity
const (
	MsgInfoVerbose Msg = C.CL_MSG_INFO_VERBOSE
	MsgWarn            = C.CL_MSG_WARN
	NsgError           = C.CL_MSG_ERROR
)

// CallbackMsg will be called instead of logging to stderr.
// Messages of lower severity than specified are logged as usual.
// This must be called before going multithreaded.
// Callable before cl_init, if you want to log messages from cl_init() itself.
//
// You can use context of cl_scandesc_callback to convey more information to the callback (such as the filename!)
// Note: setting a 2nd callbacks overwrites previous, multiple callbacks are not
// supported
type CallbackMsg func(m Msg, full, msg string, context interface{})

// CallbackHash is a callback that provides hash statistics for a particular file
type CallbackHash func(fd int, size uint64, md5 []byte, virusName string, context interface{})

// CallbackPread is a callback that will be called by ClamAV to fill in part of an object represented by an fmap handle (file in memory, memory location, etc)
type CallbackPread func(handle *interface{}, buf []byte, offset int64) int64

// CallbackMeta is an archive member metadata callback. Return Virus to blacklist,
// Clean to continue scanning
//
// NB: not exported in libclamav...
//type CallbackMeta func(containerType string, containerSize uint64, filename string, realSize uint64, encrypted bool, containerFilepos uint64, context interface{})
