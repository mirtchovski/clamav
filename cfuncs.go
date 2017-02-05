package clamav

/*
#include <clamav.h>
#include <stdlib.h>

extern cl_error_t prescanCallback(int fd, const char *ftype, void *context);
cl_error_t prescan_cgo(int fd, const char *ftype, void *context)
{
	return prescanCallback(fd, ftype, context);
}

extern cl_error_t postscanCallback(int fd, int result, char *virname, void *context);
cl_error_t postscan_cgo(int fd, int result, char *virname, void *context)
{
	return postscanCallback(fd, result, virname, context);
}

extern cl_error_t precacheCallback(int fd, const char *ftype, void *context);
off_t precache_cgo(int fd, const char *ftype, void *context)
{
	return precacheCallback(fd, ftype, context);
}

extern off_t preadCallback(void* handle, void *buf, size_t count, off_t offset);
off_t pread_cgo(void* handle, void *buf, size_t count, off_t offset)
{
	return preadCallback(handle, buf, count, offset);
}

extern void hashCallback(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context);
void hash_cgo(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context)
{
	return hashCallback(fd, size, md5, virname, context);
}
*/
import "C"
