/*
 * This software is copyright (c) 2008, 2009 by Leon Timmermans <leont@cpan.org>.
 *
 * This is free software; you can redistribute it and/or modify it under
 * the same terms as perl itself.
 *
 */

#ifdef __CYGWIN__
#	undef WIN32
#	undef _WIN32
#endif

#include <assert.h>
#ifdef WIN32
#	include <windows.h>
#	include <io.h>
#	define PROT_NONE  0
#	define PROT_READ  1
#	define PROT_WRITE 2
#	define PROT_EXEC  4
#	define MAP_SHARED  0
#	define MAP_PRIVATE 1
#	define MAP_ANONYMOUS 2
#else /* WIN32 */
#	include <sys/types.h>
#	include <sys/mman.h>
#	include <unistd.h>
#endif /* WIN32 */

#ifndef MAP_ANONYMOUS
#	define MAP_ANONYMOUS MAP_ANON
#elif !defined MAP_ANON
#	define MAP_ANON MAP_ANONYMOUS
#endif /* MAP_ANONYMOUS */

#ifndef MAP_FILE
#	define MAP_FILE 0
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifndef SvPV_free
#	define SvPV_free(arg) sv_setpvn_mg(arg, NULL, 0);
#endif

#define MMAP_MAGIC_NUMBER 0x4c54

struct mmap_info {
	void* real_address;
	void* fake_address;
	size_t real_length;
	size_t fake_length;
#ifdef USE_ITHREADS
	perl_mutex count_mutex;
	perl_mutex data_mutex;
	perl_cond cond;
	int count;
#endif
};

#ifdef WIN32

static void croak_sys(pTHX_ const char* format) {
	DWORD last_error = GetLastError(); 
	char buffer[128];

	DWORD format_flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	int length = FormatMessage(format_flags, NULL, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)buffer, sizeof buffer, NULL);
	if (buffer[length - 2] == '\r')
		buffer[length - 2] =  '\0';

	Perl_croak(aTHX_ format, buffer);
}

static DWORD page_size() {
	static DWORD pagesize = 0;
	if (pagesize == 0) {
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		pagesize = info.dwPageSize;
	}
	return pagesize;
}

#define munmap(address, length) ( UnmapViewOfFile(address) ? 0 : -1 )
#define msync(address, length, flags) ( FlushViewOfFile(address, length) ? 0 : -1 ) 
#define mlock(address, length) ( VirtualLock(address, length) ? 0 : -1 )
#define munlock(address, length) ( VirtualUnlock(address, length) ? 0 : -1 )

#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE 0
#endif

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
#else

static void croak_sys(pTHX_ const char* format) {
	char buffer[128];
#ifdef _GNU_SOURCE
	const char* message = strerror_r(errno, buffer, sizeof buffer);
	Perl_croak(aTHX_ format, message);
#else
	strerror_r(errno, buffer, sizeof buffer);
	Perl_croak(aTHX_ format, buffer);
#endif
}

static size_t page_size() {
	static size_t pagesize = 0;
	if (pagesize == 0) {
		pagesize = sysconf(_SC_PAGESIZE);
	}
	return pagesize;
}
#endif

#define PROT_ALL (PROT_READ | PROT_WRITE | PROT_EXEC)

static void reset_var(SV* var, struct mmap_info* info) {
	SvPVX(var) = info->fake_address;
	SvLEN(var) = 0;
	SvCUR(var) = info->fake_length;
	SvPOK_only(var);
}

static int mmap_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (SvPVX(var) != info->fake_address) {
		if (ckWARN(WARN_SUBSTR)) {
			Perl_warn(aTHX_ "Writing directly to a to a memory mapped file is not recommended");
			if (SvLEN(var) > info->fake_length)
				Perl_warn(aTHX_ "Truncating new value to size of the memory map");
		}

		Copy(SvPVX(var), info->fake_address, MIN(SvLEN(var) - 1, info->fake_length), char);
		SvPV_free(var);
		reset_var(var, info);
	}
	return 0;
}

static U32 mmap_length(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	return info->fake_length;
}

static int mmap_free(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
#ifdef USE_ITHREADS
	MUTEX_LOCK(&info->count_mutex);
	if (--info->count == 0) {
		if (munmap(info->real_address, info->real_length) == -1)
			croak_sys(aTHX_ "Could not munmap: %s");
		COND_DESTROY(&info->cond);
		MUTEX_DESTROY(&info->data_mutex);
		MUTEX_UNLOCK(&info->count_mutex);
		MUTEX_DESTROY(&info->count_mutex);
		Safefree(info);
	}
	else {
		if (msync(info->real_address, info->real_length, MS_ASYNC) == -1)
			croak_sys(aTHX_ "Could not msync: %s");
		MUTEX_UNLOCK(&info->count_mutex);
	}
#else
	if (munmap(info->real_address, info->real_length) == -1)
		croak_sys(aTHX_ "Could not munmap: %s");
	Safefree(info);
#endif 
	SvPVX(var) = NULL;
	SvCUR(var) = 0;
	return 0;
}

#ifdef USE_ITHREADS
static int mmap_dup(pTHX_ MAGIC* magic, CLONE_PARAMS* param) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	MUTEX_LOCK(&info->count_mutex);
	assert(info->count);
	++info->count;
	MUTEX_UNLOCK(&info->count_mutex);
	return 0;
}
#else
#define mmap_dup 0
#endif

static const MGVTBL mmap_read_table  = { NULL, NULL,       mmap_length, mmap_free, mmap_free, 0, mmap_dup };
static const MGVTBL mmap_write_table = { NULL, mmap_write, mmap_length, mmap_free, mmap_free, 0, mmap_dup };

static void check_new_variable(pTHX_ SV* var) {
	if (SvTYPE(var) > SVt_PVMG && SvTYPE(var) != SVt_PVLV)
		Perl_croak(aTHX_ "Trying to map into a nonscalar!\n");
	if (SvMAGICAL(var) && mg_find(var, PERL_MAGIC_uvar))
		sv_unmagic(var, PERL_MAGIC_uvar);
	if (SvPOK(var)) 
		SvPV_free(var);
	sv_upgrade(var, SVt_PVMG);
}

static void* do_mapping(pTHX_ size_t length, int prot, int flags, int fd, off_t offset) {
	void* address;
#ifdef WIN32
	prot &= PROT_ALL;
	HANDLE file = (flags & MAP_ANONYMOUS) ? INVALID_HANDLE_VALUE : (HANDLE)_get_osfhandle(fd);
	HANDLE mapping = CreateFileMapping(file, NULL, winflags[prot].createflag, 0, length, NULL);
	if (mapping == NULL)
		croak_sys(aTHX_ "Could not mmap: %s\n");
	DWORD viewflag = (flags & MAP_PRIVATE) ? (FILE_MAP_COPY | ( prot | PROT_EXEC ? FILE_MAP_EXECUTE : 0 ) ) : winflags[prot].viewflag;
	address = MapViewOfFile(mapping, viewflag, 0, offset, length);
	CloseHandle(mapping);
	if (address == NULL)
#else
	address = mmap(0, length, prot, flags, fd, offset);
	if (address == MAP_FAILED)
#endif
		croak_sys(aTHX_ "Could not mmap: %s\n");
	return address;
}

static struct mmap_info* initialize_mmap_info(void* address, size_t length, ptrdiff_t correction) {
	struct mmap_info* magical;
	New(0, magical, 1, struct mmap_info);
	magical->real_address = address;
	magical->fake_address = address + correction;
	magical->real_length = length + correction;
	magical->fake_length = length;
#ifdef USE_ITHREADS
	MUTEX_INIT(&magical->count_mutex);
	MUTEX_INIT(&magical->data_mutex);
	COND_INIT(&magical->cond);
	magical->count = 1;
#endif
	return magical;
}

static void add_magic(pTHX_ SV* var, struct mmap_info* magical, int writable) {
	const MGVTBL* table = writable ? &mmap_write_table : &mmap_read_table;
	MAGIC* magic = sv_magicext(var, NULL, PERL_MAGIC_uvar, table, (const char*) magical, 0);
	magic->mg_private = MMAP_MAGIC_NUMBER;
#ifdef USE_ITHREADS
	magic->mg_flags |= MGf_DUP;
#endif
	if (!writable)
		SvREADONLY_on(var);
}

static SV* deref_var(pTHX_ SV* var_ref) {
	if (!SvROK(var_ref))
		Perl_croak(aTHX_ "Invalid argument!");
	return SvRV(var_ref);
}

static struct mmap_info* get_mmap_magic(pTHX_ SV* var, const char* funcname) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_find(var, PERL_MAGIC_uvar)) == NULL ||  magic->mg_private != MMAP_MAGIC_NUMBER)
		Perl_croak(aTHX_ "Could not %s: this variable is not memory mapped", funcname);
	return (struct mmap_info*) magic->mg_ptr;
}

static void magic_end(pTHX_ void* info) {
	MUTEX_UNLOCK(&((struct mmap_info*)info)->data_mutex);
}

#define YES &PL_sv_yes

#define MAP_CONSTANT(cons) hv_store(map_constants, #cons, sizeof #cons - 1, newSVuv(cons), 0)
#define ADVISE_CONSTANT(key, value) hv_store(advise_constants, key, sizeof key - 1, newSVuv(value), 0)

MODULE = File::Map				PACKAGE = File::Map

PROTOTYPES: DISABLED

BOOT:
	HV* map_constants = get_hv("File::Map::MAP_CONSTANTS", TRUE);
	MAP_CONSTANT(PROT_NONE);
	MAP_CONSTANT(PROT_READ);
	MAP_CONSTANT(PROT_WRITE);
	MAP_CONSTANT(PROT_EXEC);
	MAP_CONSTANT(MAP_ANONYMOUS);
	MAP_CONSTANT(MAP_SHARED);
	MAP_CONSTANT(MAP_PRIVATE);
	MAP_CONSTANT(MAP_ANON);
	MAP_CONSTANT(MAP_FILE);
	/**/
#ifdef MADV_NORMAL
	HV* advise_constants = get_hv("File::Map::ADVISE_CONSTANTS", TRUE | GV_ADDMULTI );
	ADVISE_CONSTANT("normal", MADV_NORMAL);
	ADVISE_CONSTANT("random", MADV_RANDOM);
	ADVISE_CONSTANT("sequential", MADV_SEQUENTIAL);
	ADVISE_CONSTANT("willneed", MADV_WILLNEED);
	ADVISE_CONSTANT("dontneed", MADV_DONTNEED);
#ifdef MADV_REMOVE
	ADVISE_CONSTANT("remove", MADV_REMOVE);
#endif
#ifdef MADV_DONTFORK
	ADVISE_CONSTANT("dontfork", MADV_DONTFORK);
#endif
#ifdef MADV_DOFORK
	ADVISE_CONSTANT("dofork", MADV_DOFORK);
#endif
#endif

SV*
_mmap_impl(var, length, prot, flags, fd, offset)
	SV* var = deref_var(aTHX_ ST(0));
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
	CODE:
		check_new_variable(aTHX_ var);
		
		ptrdiff_t correction = offset % page_size();
		void* address = do_mapping(aTHX_ length + correction, prot, flags, fd, offset - correction);
		
		struct mmap_info* magical = initialize_mmap_info(address, length, correction);
		reset_var(var, magical);
		add_magic(aTHX_ var, magical, prot & PROT_WRITE);
		ST(0) = YES;

SV*
sync(var, sync = YES)
	SV* var = deref_var(aTHX_ ST(0));
	SV* sync;
	PROTOTYPE: \$@
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "sync");
		if (msync(info->real_address, info->real_length, SvTRUE(sync) ? MS_SYNC : MS_ASYNC ) == -1)
			croak_sys(aTHX_ "Could not sync: %s");
		ST(0) = YES;

#ifdef __linux__
SV*
remap(var, new_size)
	SV* var = deref_var(aTHX_ ST(0));
	size_t new_size;
	PROTOTYPE: \$@
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "remap");
		if (mremap(info->real_address, info->real_length, new_size + (info->real_length - info->fake_length), 0) == MAP_FAILED)
			croak_sys(aTHX_ "Could not remap: %s");
		ST(0) = YES;

#endif /* __linux__ */

SV*
unmap(var)
	SV* var = deref_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE: 
		get_mmap_magic(aTHX_ var, "unmap");
		sv_unmagic(var, PERL_MAGIC_uvar);
		ST(0) = YES;

SV*
pin(var)
	SV* var = deref_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE: 
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "pin");
		if (mlock(info->real_address, info->real_length) == -1)
			croak_sys(aTHX_ "Could not mlock: %s");
		ST(0) = YES;

SV*
unpin(var)
	SV* var = deref_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "unpin");
		if (munlock(info->real_address, info->real_length) == -1)
			croak_sys(aTHX_ "Could not munlock: %s");
		ST(0) = YES;

SV*
advise(var, name)
	SV* var = deref_var(aTHX_ ST(0));
	SV* name;
	PROTOTYPE: \$@
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "advise");
#ifdef MADV_NORMAL
		HV* constants = get_hv("File::Map::ADVISE_CONSTANTS", FALSE);
		HE* value = hv_fetch_ent(constants, name, 0, 0);
		if (!value)
			Perl_croak(aTHX_ "Invalid key for advise");
		if (madvise(info->real_address, info->real_length, SvUV(HeVAL(value)) == -1))
			croak_sys(aTHX_ "Could not madvice: %s");
#endif
		ST(0) = YES;

void
lock_map(var)
	SV* var = deref_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "lock_map");
#ifdef USE_ITHREADS
		LEAVE;
		SAVEDESTRUCTOR_X(magic_end, info);
		MUTEX_LOCK(&info->data_mutex);
		ENTER;
#endif

#ifdef USE_ITHREADS
void
wait_until(block, var)
	SV* block;
	SV* var = deref_var(aTHX_ ST(1));
	PROTOTYPE: &\$
	PPCODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "wait_until");
		SAVESPTR(DEFSV);
		DEFSV = var;
		while (1) {
			PUSHMARK(SP);
			call_sv(block, G_SCALAR | G_NOARGS);
			SPAGAIN;
			if (SvTRUE(TOPs))
				break;
			POPs;
			COND_WAIT(&info->cond, &info->data_mutex);
		}

void
notify(var)
	SV* var = deref_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "notify");
		COND_SIGNAL(&info->cond);

void
broadcast(var)
	SV* var = deref_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "broadcast");
		COND_BROADCAST(&info->cond);

#endif /* USE ITHREADS */
