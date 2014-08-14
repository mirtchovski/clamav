// Copyright 2013 the Go ClamAV authors
// Use of this source code is governed by a
// license that can be found in the LICENSE file.
package clamav

/*
#include <clamav.h>
#include <stdlib.h>

cl_error_t precache_cgo(int fd, const char *type, void *context);
cl_error_t prescan_cgo(int fd, const char *type, void *context);
cl_error_t postscan_cgo(int fd, int result, char *virname, void *context);

void hash_cgo(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type cbData struct {
	cb interface{} // callback function
}

var callbacks = map[string]interface{}{
	"precache": nil,
	"prescan":  nil,
	"postscan": nil,
	"sigload":  nil,
	"hash":     nil,
	"msg":      nil,
	"meta":     nil,
}

//export precache_cb
func precache_cb(fd C.int, ftype *C.char, context unsafe.Pointer) C.cl_error_t {
	v := callbacks["precache"]
	if v == nil {
		return Clean
	}
	return C.cl_error_t(v.(CallbackPreCache)(int(fd), C.GoString(ftype), (*interface{})(context)))
}

func (e *Engine) SetPreCacheCallback(cb CallbackPreCache) {
	callbacks["precache"] = cb

	C.cl_engine_set_clcb_pre_cache((*C.struct_cl_engine)(unsafe.Pointer(e)), (C.clcb_pre_cache)(unsafe.Pointer(C.precache_cgo)))
}

//export prescan_cb
func prescan_cb(fd C.int, ftype *C.char, context unsafe.Pointer) C.cl_error_t {
	v := callbacks["prescan"]
	if v == nil {
		return Clean
	}
	return C.cl_error_t(v.(CallbackPreScan)(int(fd), C.GoString(ftype), (*interface{})(context)))
}

// SetPreScanCallback will set the callback function ClamAV will call before a
// scan commences to cb
func (e *Engine) SetPreScanCallback(cb CallbackPreScan) {
	callbacks["prescan"] = cb
	C.cl_engine_set_clcb_pre_scan((*C.struct_cl_engine)(unsafe.Pointer(e)), C.clcb_pre_scan(unsafe.Pointer(C.prescan_cgo)))
}

//export postscan_cb
func postscan_cb(fd, result C.int, virname *C.char, context unsafe.Pointer) C.cl_error_t {
	v := callbacks["postscan"]
	if v == nil {
		return Clean
	}
	return C.cl_error_t(v.(CallbackPostScan)(int(fd), ErrorCode(result), C.GoString(virname), (*interface{})(context)))
}

// SetPostScanCallback will set the callback function ClamAV will call before the
// cache is consulted for a particular scan to cb
func (e *Engine) SetPostScanCallback(cb CallbackPostScan) {
	callbacks["postscan"] = cb
	C.cl_engine_set_clcb_post_scan((*C.struct_cl_engine)(unsafe.Pointer(e)), (C.clcb_post_scan)(unsafe.Pointer(C.postscan_cgo)))
}

// PreadHandleCallbacks stores a pread function associated with each handle passed
// through FmapOpenHandle. The callbacks are used to read from the file/memory location
// associated with the handle
var preadHandleCallbacks map[*interface{}]CallbackPread = map[*interface{}]CallbackPread{}

//export pread_cb
func pread_cb(handle unsafe.Pointer, buf unsafe.Pointer, count C.size_t, offset C.off_t) C.off_t {
	v, ok := preadHandleCallbacks[(*interface{})(handle)]
	if !ok {
		return -1 // couldn't find callback
	}
	return C.off_t(v((*interface{})(handle), C.GoBytes(buf, C.int(count)), int64(offset)))
}

// SetSigLoadCallback will set the callback function ClamAV will call before the
// cache is consulted for a particular scan to cb
// func (e *Engine) SetSigLoadCallback(cb CallbackSigLoad) ErrorCode {
//	return 0
// }

//export msgcb
var msgcb = func(severity C.enum_cl_msg, fullmsg *C.char, msg *C.char, context unsafe.Pointer) {
	v := callbacks["msg"]
	if v == nil {
		return
	}
	v.(CallbackMsg)(Msg(severity), C.GoString(fullmsg), C.GoString(msg), (*interface{})(context))
}

// SetMsgCallback will set the callback function ClamAV will call for any error and warning
// messages. The specified callback will be called instead of logging to stderr.
// Messages of lower severity than specified are logged as usual.
//
// Just like with cl_debug() this must be called before going multithreaded.
// Callable before cl_init, if you want to log messages from cl_init() itself.
func SetMsgCallback(cb CallbackMsg) {
	callbacks["msg"] = cb
	C.cl_set_clcb_msg((C.clcb_msg)(unsafe.Pointer(&msgcb)))
}

//export hash_cb
func hash_cb(fd C.int, size C.ulonglong, md5 *C.uchar, virname *C.char, context unsafe.Pointer) {
	v := callbacks["hash"]
	if v == nil {
		return
	}
	v.(CallbackHash)(int(fd), uint64(size), []byte(C.GoBytes(unsafe.Pointer(md5), 16)), C.GoString(virname), (*interface{})(context))
}

// SetHashCallback will set the callback function ClamAV will call with statistics
// about the scanned file
func (e *Engine) SetHashCallback(cb CallbackHash) {
	callbacks["hash"] = cb

	C.cl_engine_set_clcb_hash((*C.struct_cl_engine)(unsafe.Pointer(e)), (C.clcb_hash)(unsafe.Pointer(C.hash_cgo)))
}

/* FmapOpenHandle opens a file map for scanning custom data accessed by a handle and pread (lseek +
 * read)-like interface, for example a WIN32 HANDLE.
 * By default fmap will use aging to discard old data, unless you tell it not
 * to via the parameter "age". The handle will be passed to the callback each time.
 */
func FmapOpenHandle(handle *interface{}, offset int64, length uint32, cb CallbackPread, age bool) *Fmap {
	return nil
}

/* FmapOpenMemory opens a map for scanning custom data, where the data is already in memory,
 * either in the form of a buffer, a memory mapped file, etc.
 * Note that the memory [start, start+len) must be the _entire_ file,
 * you can't give it parts of a file and expect detection to work.
 */
func FmapOpenMemory(buf []byte) *Fmap {
	if len(buf) == 0 {
		return nil
	}
	return (*Fmap)(C.cl_fmap_open_memory(unsafe.Pointer(&buf[0]), C.size_t(len(buf))))
}

/* Close resources associated with the map, you should release any resources
 * you hold only after (handles, maps) calling this function */
func (f *Fmap) Close() {
	C.cl_fmap_close((*C.struct_cl_fmap)(f))
}

/* ScanMapCb scans custom data */
func (e *Engine) ScanMap(fmap *Fmap, opts uint, context *interface{}) (string, uint, error) {
	var name *C.char
	var scanned C.ulong
	err := ErrorCode(C.cl_scanmap_callback((*C.cl_fmap_t)(fmap), &name, &scanned, (*C.struct_cl_engine)(e), C.uint(opts), unsafe.Pointer(context)))
	if err == Success {
		return "", 0, nil
	}
	if err == Virus {
		return C.GoString(name), uint(scanned), fmt.Errorf(StrError(err))
	}
	return "", 0, fmt.Errorf(StrError(err))
}

/* These below do not seem to exist in libclamav.a
*
* func metacb(container_type *C.char, fsize_container C.ulong, filename *C.char,
*			  realSize C.ulong,  is_encrypted C.int, filepos_container C.uint, _ unsafe.Pointer) ErrorCode {
*	var v cbData
*	if v, ok := cb["meta"]; !ok || v.cb == nil {
*		return
*	}
*	encr := false
*	if(is_encrypted > 0) {
*		encr = true
*	}
*	v.cb(C.GoString(container_type), uint64(fsize_container), C.GoString(filename), uint64(fsize_real), encr, uint64(filepos_container), v.ctx)
*}
*
*func (e *Engine) SetMetaCallback(cb CallbackMeta, context interface{}) ErrorCode {
*	var v cbData
*	if v, ok := cb["meta"]; !ok || v.cb == nil {
*		return
*	}
*	v.cb = cb
*	v.ctx = context
*
*	return C.cl_engine_set_clcb_meta((C.clcb_meta)(unsafe.Pointer(metacb)))
*}
 */
