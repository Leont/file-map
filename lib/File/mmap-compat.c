#if defined(WIN32) && !defined(__CYGWIN__)

#  include <windows.h>
#  include <io.h>
#  define PROT_NONE  0
#  define PROT_READ  1
#  define PROT_WRITE 2
#  define PROT_EXEC  4
#  define MAP_SHARED  0
#  define MAP_PRIVATE 1
#  define MAP_ANONYMOUS 2
#  define MAP_FAILED ((void *) -1)

#  define PROT_ALL (PROT_READ | PROT_WRITE | PROT_EXEC)
#    ifndef FILE_MAP_EXECUTE
#      define FILE_MAP_EXECUTE 0
#    endif
#  define BITS32_MASK 0xFFFFFFFF


static DWORD page_size() {
	static DWORD pagesize = 0;
	if (pagesize == 0) {
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		pagesize = info.dwPageSize;
	}
	return pagesize;
}

static DWORD old_protect;

static const struct {
	DWORD createflag;
	DWORD viewflag;
} winflags[] = {
	{ 0             ,         0 },                                     /* PROT_NONE */
	{ PAGE_READONLY ,         FILE_MAP_READ       },                   /* PROT_READ */
	{ PAGE_READWRITE,         FILE_MAP_WRITE      },                   /* PROT_WRITE */
	{ PAGE_READWRITE,         FILE_MAP_ALL_ACCESS },                   /* PROT_READ | PROT_WRITE */
	{ PAGE_EXECUTE_READ     , FILE_MAP_READ       | FILE_MAP_EXECUTE}, /* PROT_NONE | PROT_EXEC */
	{ PAGE_EXECUTE_READ     , FILE_MAP_READ       | FILE_MAP_EXECUTE}, /* PROT_READ | PROT_EXEC */
	{ PAGE_EXECUTE_READWRITE, FILE_MAP_WRITE      | FILE_MAP_EXECUTE}, /* PROT_WRITE | PROT_EXEC */
	{ PAGE_EXECUTE_READWRITE, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE}, /* PROT_READ| PROT_WRITE | PROT_EXEC */
};

void* mmap(void* address, size_t length, int prot, int flags, int fd, unsigned long long offset) {
	HANDLE file;
	HANDLE mapping;
	DWORD viewflag;
	unsigned long long maxsize = offset + length;
	prot &= PROT_ALL;
	file = (flags & MAP_ANONYMOUS) ? INVALID_HANDLE_VALUE : (HANDLE)_get_osfhandle(fd);
	mapping = CreateFileMapping(file, NULL, winflags[prot].createflag, maxsize >> 32, maxsize & BITS32_MASK, NULL);
	if (mapping == NULL)
		return MAP_FAILED;
	viewflag = (flags & MAP_PRIVATE) ? (FILE_MAP_COPY | ( prot & PROT_EXEC ? FILE_MAP_EXECUTE : 0 ) ) : winflags[prot].viewflag;
	address = MapViewOfFile(mapping, viewflag, offset >> 32, offset & BITS32_MASK, length);
	CloseHandle(mapping);
	if (address == NULL)
		return MAP_FAILED;
	return address;
}

#  define munmap(address, length) ( UnmapViewOfFile(address) ? 0 : -1 )
#  define msync(address, length, flags) ( FlushViewOfFile(address, length) ? 0 : -1 )
#  define mlock(address, length) ( VirtualLock(address, length) ? 0 : -1 )
#  define munlock(address, length) ( VirtualUnlock(address, length) ? 0 : -1 )
#  define mprotect(address, length, prot) ( VirtualProtect(address, length, winflags[prot & PROT_ALL].createflag, &old_protect) ? 0 : -1 )

#define madvise(address, length, advice) 0

#else /* WIN32 */

#  include <string.h>
#  include <sys/types.h>
#  include <sys/mman.h>
#  include <unistd.h>

static size_t page_size() {
	static size_t pagesize = 0;
	if (pagesize == 0)
		pagesize = sysconf(_SC_PAGESIZE);
	return pagesize;
}

#ifdef VMS
#  define madvise(address, length, advice) 0
#elif defined(__CYGWIN__) || defined(__QNX__)
#	define madvise posix_madvise
#endif

#endif /* WIN32 */

#ifndef MADV_NORMAL
#	define MADV_NORMAL 0
#	define MADV_RANDOM 0
#	define MADV_SEQUENTIAL 0
#	define MADV_WILLNEED 0
#	define MADV_DONTNEED 0
#endif

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#elif !defined MAP_ANON
#  define MAP_ANON MAP_ANONYMOUS
#endif /* MAP_ANONYMOUS */

#ifndef MAP_FILE
#  define MAP_FILE 0
#endif

#ifndef MAP_VARIABLE
#  define MAP_VARIABLE 0
#endif

