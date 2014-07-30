package clamav

/*
#include <clamav.h>
#include <stdlib.h>

extern cl_error_t prescan_cb(int fd, const char *ftype, void *context);
cl_error_t prescan_cgo(int fd, const char *ftype, void *context)
{
	return prescan_cb(fd, ftype, context);
}

extern cl_error_t postscan_cb(int fd, int result, char *virname, void *context);
cl_error_t postscan_cgo(int fd, int result, char *virname, void *context)
{
	return postscan_cb(fd, result, virname, context);
}

extern cl_error_t precache_cb(int fd, const char *ftype, void *context);
off_t precache_cgo(int fd, const char *ftype, void *context)
{
	return precache_cb(fd, ftype, context);
}

extern off_t pread_cb(void* handle, void *buf, size_t count, off_t offset);
off_t pread_cgo(void* handle, void *buf, size_t count, off_t offset)
{
	return pread_cb(handle, buf, count, offset);
}

extern void hash_cb(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context);
void hash_cgo(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context)
{
	return hash_cb(fd, size, md5, virname, context);
}
*/
import "C"
