/*
 * This software is copyright (c) 2008, 2009 by Leon Timmermans <leont@cpan.org>.
 *
 * This is free software; you can redistribute it and/or modify it under
 * the same terms as perl itself.
 *
 */

#if defined(linux) && !defined(_GNU_SOURCE)
#		define _GNU_SOURCE
#endif

#ifdef __CYGWIN__
#	undef WIN32
#	undef _WIN32
#	define madvise posix_madvise
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
#	include <string.h>
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

#ifndef MAP_VARIABLE
#	define MAP_VARIABLE 0
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

#ifndef SV_CHECK_THINKFIRST_COW_DROP
#define SV_CHECK_THINKFIRST_COW_DROP(sv) SV_CHECK_THINKFIRST(sv)
#endif

struct mmap_info {
	void* real_address;
	void* fake_address;
	size_t real_length;
	size_t fake_length;
	int flags;
#ifdef USE_ITHREADS
	perl_mutex count_mutex;
	perl_mutex data_mutex;
	PerlInterpreter* owner;
	perl_cond cond;
	int count;
#endif
};

#ifdef WIN32

static void get_sys_error(char* buffer, size_t buffer_size) {
	DWORD last_error = GetLastError(); 

	DWORD format_flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	int length = FormatMessage(format_flags, NULL, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)buffer, buffer_size, NULL);
	if (buffer[length - 2] == '\r') {
		buffer[length - 2] =  '\0';
	}
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

static DWORD old_protect;

#define munmap(address, length) ( UnmapViewOfFile(address) ? 0 : -1 )
#define msync(address, length, flags) ( FlushViewOfFile(address, length) ? 0 : -1 ) 
#define mlock(address, length) ( VirtualLock(address, length) ? 0 : -1 )
#define munlock(address, length) ( VirtualUnlock(address, length) ? 0 : -1 )
#define mprotect(address, length, prot) ( VirtualProtect(address, length, winflags[prot & PROT_ALL].createflag, &old_protect) ? 0 : -1 )

#ifndef FILE_MAP_EXECUTE
#	define FILE_MAP_EXECUTE 0
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

#define madvise(address, length, advice) 0

#else

static void S_get_sys_error(pTHX_ char* buffer, size_t buffer_size) {
#ifdef HAS_STRERROR_R
#	if STRERROR_R_PROTO == REENTRANT_PROTO_B_IBW
	const char* message = strerror_r(errno, buffer, buffer_size);
	if (message != buffer)
		memcpy(buffer, message, buffer_size);
#	else
	strerror_r(errno, buffer, buffer_size);
#	endif
#else
	const char* message = strerror(errno);
	strncpy(buffer, message, buffer_size - 1);
	buffer[buffer_size - 1] = '\0';
#endif
}
#define get_sys_error(buffer, buffer_size) S_get_sys_error(aTHX_ buffer, buffer_size)

static size_t page_size() {
	static size_t pagesize = 0;
	if (pagesize == 0) {
		pagesize = sysconf(_SC_PAGESIZE);
	}
	return pagesize;
}
#endif

#ifdef VMS
#define madvise(address, length, advice) 0
#endif

#ifndef MADV_NORMAL
#	define MADV_NORMAL 0
#	define MADV_RANDOM 0
#	define MADV_SEQUENTIAL 0
#	define MADV_WILLNEED 0
#	define MADV_DONTNEED 0
#endif

static void S_die_sys(pTHX_ const char* format) {
	char buffer[128];
	get_sys_error(buffer, sizeof buffer);
	Perl_croak(aTHX_ format, buffer);
}
#define die_sys(format) S_die_sys(aTHX_ format)

static void real_croak_sv(pTHX_ SV* value) {
	dSP;
	PUSHMARK(SP);
	XPUSHs(value);
	PUTBACK;
	call_pv("Carp::croak", G_VOID | G_DISCARD);
}

static void real_croak_pv(pTHX_ const char* value) {
	real_croak_sv(aTHX_ sv_2mortal(newSVpv(value, 0)));
}

static void croak_sys(pTHX_ const char* format) {
	char buffer[128];
	SV* tmp;
	get_sys_error(buffer, sizeof buffer);
	tmp = sv_2mortal(newSVpvf(format, buffer, NULL));
	real_croak_sv(aTHX_ tmp);
}

#define PROT_ALL (PROT_READ | PROT_WRITE | PROT_EXEC)

static void reset_var(SV* var, struct mmap_info* info) {
	SvPVX(var) = info->fake_address;
	SvLEN(var) = 0;
	SvCUR(var) = info->fake_length;
	SvPOK_only_UTF8(var);
}

static void mmap_fixup(pTHX_ SV* var, struct mmap_info* info, const char* string, STRLEN len) {
	if (ckWARN(WARN_SUBSTR)) {
		Perl_warn(aTHX_ "Writing directly to a memory mapped file is not recommended");
		if (SvCUR(var) > info->fake_length)
			Perl_warn(aTHX_ "Truncating new value to size of the memory map");
	}

	if (string && len)
		Copy(string, info->fake_address, MIN(len, info->fake_length), char);
	SV_CHECK_THINKFIRST_COW_DROP(var);
	if (SvROK(var))
		sv_unref_flags(var, SV_IMMEDIATE_UNREF);
	if (SvPOK(var))
		SvPV_free(var);
	reset_var(var, info);
}

static int mmap_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (!SvOK(var))
		mmap_fixup(aTHX_ var, info, NULL, 0);
	else if (!SvPOK(var)) {
		STRLEN len;
		const char* string = SvPV(var, len);
		mmap_fixup(aTHX_ var, info, string, len);
	}
	else if (SvPVX(var) != info->fake_address)
		mmap_fixup(aTHX_ var, info, SvPVX(var), SvCUR(var));
	else
		SvPOK_only_UTF8(var);
	return 0;
}

static int empty_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (!SvPOK(var) || sv_len(var) != 0) {
		sv_setpvn(var, "", 0);
		if (ckWARN(WARN_SUBSTR))
			Perl_warn(aTHX_ "Can't overwrite an empty map");
	}
	return 0;
}

static int mmap_clear(pTHX_ SV* var, MAGIC* magic) {
	Perl_die(aTHX_ "Can't clear a mapped variable");
	return 0;
}

static int mmap_free(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
#ifdef USE_ITHREADS
	MUTEX_LOCK(&info->count_mutex);
	if (--info->count == 0) {
		if (munmap(info->real_address, info->real_length) == -1)
			die_sys("Could not unmap: %s");
		COND_DESTROY(&info->cond);
		MUTEX_DESTROY(&info->data_mutex);
		MUTEX_UNLOCK(&info->count_mutex);
		MUTEX_DESTROY(&info->count_mutex);
		PerlMemShared_free(info);
	}
	else {
		if (msync(info->real_address, info->real_length, MS_ASYNC) == -1)
			die_sys("Could not sync: %s");
		MUTEX_UNLOCK(&info->count_mutex);
	}
#else
	if (munmap(info->real_address, info->real_length) == -1)
		die_sys("Could not unmap: %s");
	PerlMemShared_free(info);
#endif 
	SvREADONLY_off(var);
	SvPVX(var) = NULL;
	SvCUR(var) = 0;
	return 0;
}

static int empty_free(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
#ifdef USE_ITHREADS
	MUTEX_LOCK(&info->count_mutex);
	if (--info->count == 0) {
		COND_DESTROY(&info->cond);
		MUTEX_DESTROY(&info->data_mutex);
		MUTEX_UNLOCK(&info->count_mutex);
		MUTEX_DESTROY(&info->count_mutex);
		PerlMemShared_free(info);
	}
	else {
		MUTEX_UNLOCK(&info->count_mutex);
	}
#else
	PerlMemShared_free(info);
#endif 
	SvREADONLY_off(var);
	SvPV_free(var);
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

#ifdef MGf_LOCAL
static int mmap_local(pTHX_ SV* var, MAGIC* magic) {
	Perl_croak(aTHX_ "Can't localize file map");
}
#define mmap_local_tail , mmap_local
#else
#define mmap_local_tail
#endif

static const MGVTBL mmap_table  = { 0, mmap_write,  0, mmap_clear, mmap_free,  0, mmap_dup mmap_local_tail };
static const MGVTBL empty_table = { 0, empty_write, 0, mmap_clear, empty_free, 0, mmap_dup mmap_local_tail };

static Off_t S_sv_to_offset(pTHX_ SV* var) {
#if IV_SIZE >= 8
	return (Off_t)SvUV(var);
#else
	return (Off_t)floor(SvNV(var) + 0.5); /* hic sunt dracones */
#endif
}
#define sv_to_offset(var) S_sv_to_offset(aTHX_ var)

static void check_new_variable(pTHX_ SV* var) {
	if (SvTYPE(var) > SVt_PVMG && SvTYPE(var) != SVt_PVLV)
		Perl_croak(aTHX_ "Trying to map into a nonscalar!\n");
	SV_CHECK_THINKFIRST_COW_DROP(var);
	if (SvREADONLY(var))
		Perl_croak(aTHX_ "%s", PL_no_modify);
	if (SvMAGICAL(var) && mg_find(var, PERL_MAGIC_uvar))
		sv_unmagic(var, PERL_MAGIC_uvar);
	if (SvROK(var))
		sv_unref_flags(var, SV_IMMEDIATE_UNREF);
	if (SvNIOK(var))
		SvNIOK_off(var);
	if (SvPOK(var)) 
		SvPV_free(var);
	SvUPGRADE(var, SVt_PVMG);
}

#define BITS32_MASK 0xFFFFFFFF

static void* do_mapping(pTHX_ size_t length, int prot, int flags, int fd, Off_t offset) {
	void* address;
#ifdef WIN32
	HANDLE file;
	HANDLE mapping;
	DWORD viewflag;
	Off_t maxsize = offset + length;
	prot &= PROT_ALL;
	file = (flags & MAP_ANONYMOUS) ? INVALID_HANDLE_VALUE : (HANDLE)_get_osfhandle(fd);
	mapping = CreateFileMapping(file, NULL, winflags[prot].createflag, maxsize >> 32, maxsize & BITS32_MASK, NULL);
	if (mapping == NULL)
		croak_sys(aTHX_ "Could not map: %s");
	viewflag = (flags & MAP_PRIVATE) ? (FILE_MAP_COPY | ( prot & PROT_EXEC ? FILE_MAP_EXECUTE : 0 ) ) : winflags[prot].viewflag;
	address = MapViewOfFile(mapping, viewflag, offset >> 32, offset & BITS32_MASK, length);
	CloseHandle(mapping);
	if (address == NULL)
#else
	address = mmap(0, length, prot, flags | MAP_VARIABLE, fd, offset);
	if (address == MAP_FAILED)
#endif
		croak_sys(aTHX_ "Could not map: %s");
	return address;
}

static void S_set_mmap_info(pTHX_ struct mmap_info* magical, void* address, size_t length, ptrdiff_t correction) {
	magical->real_address = address;
	magical->fake_address = (char*)address + correction;
	magical->real_length = length + correction;
	magical->fake_length = length;
#ifdef USE_ITHREADS
	MUTEX_INIT(&magical->count_mutex);
	MUTEX_INIT(&magical->data_mutex);
	COND_INIT(&magical->cond);
	magical->count = 1;
#endif
}
#define set_mmap_info(magical, addres, length, correction) S_set_mmap_info(aTHX_ magical, addres, length, correction)

static struct mmap_info* initialize_mmap_info(pTHX_ void* address, size_t length, ptrdiff_t correction, int flags) {
	struct mmap_info* magical = PerlMemShared_malloc(sizeof *magical);
	set_mmap_info(magical, address, length, correction);
	magical->flags = flags;
	return magical;
}

static void add_magic(pTHX_ SV* var, struct mmap_info* magical, const MGVTBL* table, int writable, int utf8) {
	MAGIC* magic = sv_magicext(var, NULL, PERL_MAGIC_uvar, table, (const char*) magical, 0);
	magic->mg_private = MMAP_MAGIC_NUMBER;
#ifdef MGf_LOCAL
	magic->mg_flags |= MGf_LOCAL;
#endif
#ifdef USE_ITHREADS
	magic->mg_flags |= MGf_DUP;
#endif
	SvTAINTED_on(var);
	if (utf8 && !sv_utf8_decode(var))
		Perl_croak(aTHX_ "Invalid utf8 in memory mapping");
	if (!writable)
		SvREADONLY_on(var);
}

static int _is_mappable(pTHX_ int fd) {
	Stat_t info;
	return Fstat(fd, &info) == 0 && (S_ISREG(info.st_mode) || S_ISBLK(info.st_mode));
}

#define is_mappable(fd) _is_mappable(aTHX_ fd)

static struct mmap_info* get_mmap_magic(pTHX_ SV* var, const char* funcname) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_find(var, PERL_MAGIC_uvar)) == NULL ||  magic->mg_private != MMAP_MAGIC_NUMBER)
		Perl_croak(aTHX_ "Could not %s: this variable is not memory mapped", funcname);
	return (struct mmap_info*) magic->mg_ptr;
}

#ifdef USE_ITHREADS
static void magic_end(pTHX_ void* pre_info) {
	struct mmap_info* info = (struct mmap_info*) pre_info;
	info->owner = NULL;
	MUTEX_UNLOCK(&info->data_mutex);
}
#endif

typedef struct { const char* key; size_t length; int value; } map[];

static map prots = {
	{ STR_WITH_LEN("<"), PROT_READ },
	{ STR_WITH_LEN("+<"), PROT_READ | PROT_WRITE },
	{ STR_WITH_LEN(">"), PROT_WRITE },
	{ STR_WITH_LEN("+>"), PROT_READ | PROT_WRITE },
};

static int S_protection_value(pTHX_ SV* mode, int fallback) {
	int i;
	STRLEN len;
	const char* value = SvPV(mode, len);
	for (i = 0; i < sizeof prots / sizeof *prots; ++i) {
		if (prots[i].length == len && strEQ(value, prots[i].key))
			return prots[i].value;
	}
	if (fallback && SvIOK(mode))
		return SvIV(mode);
	Perl_croak(aTHX_ "No such mode '%s' known", mode);
}
#define protection_value(prot, fallback) S_protection_value(aTHX_ prot, fallback)

#define YES &PL_sv_yes

#define MAP_CONSTANT(cons) newCONSTSUB(stash, #cons, newSVuv(cons))
#define ADVISE_CONSTANT(key, value) hv_store(advise_constants, key, sizeof key - 1, newSVuv(value), 0)

#define EMPTY_MAP(info) ((info)->real_length == 0)

#define IGNORE_EMPTY_MAP(info) STMT_START {\
	if (EMPTY_MAP(info))\
		XSRETURN_EMPTY;\
	} STMT_END

static boot(pTHX) {
	AV* constants = newAV();
	HV* stash = get_hv("File::Map::", FALSE);
	HV* advise_constants = newHV();

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
	
	hv_store(PL_modglobal, "File::Map::ADVISE_CONSTANTS", 27, (SV*)advise_constants, 0);
	ADVISE_CONSTANT("normal", MADV_NORMAL);
	ADVISE_CONSTANT("random", MADV_RANDOM);
	ADVISE_CONSTANT("sequential", MADV_SEQUENTIAL);
	ADVISE_CONSTANT("willneed", MADV_WILLNEED);
	ADVISE_CONSTANT("dontneed", MADV_DONTNEED);
	/* Linux specific advices */
#ifdef MADV_REMOVE
	ADVISE_CONSTANT("remove", MADV_REMOVE);
#endif
#ifdef MADV_DONTFORK
	ADVISE_CONSTANT("dontfork", MADV_DONTFORK);
#endif
#ifdef MADV_DOFORK
	ADVISE_CONSTANT("dofork", MADV_DOFORK);
#endif
#ifdef MADV_MERGEABLE
	ADVISE_CONSTANT("mergeable", MADV_MERGEABLE);
#endif
#ifdef MADV_UNMERGEABLE
	ADVISE_CONSTANT("unmergeable", MADV_UNMERGEABLE);
#endif
	/* BSD, Mac OS X & Solaris specific advice */
#ifdef MADV_FREE
	ADVISE_CONSTANT("free", MADV_FREE);
#endif
	/* FreeBSD specific advices */
#ifdef MADV_NOSYNC
	ADVISE_CONSTANT("nosync", MADV_NOSYNC);
#endif
#ifdef MADV_AUTOSYNC
	ADVISE_CONSTANT("autosync", MADV_AUTOSYNC);
#endif
#ifdef MADV_NOCORE
	ADVISE_CONSTANT("nocore", MADV_NOCORE);
#endif
#ifdef MADV_CORE
	ADVISE_CONSTANT("core", MADV_CORE);
#endif
#ifdef MADV_PROTECT
	ADVISE_CONSTANT("protect", MADV_PROTECT);
#endif
#ifdef MADV_SPACEAVAIL
	ADVISE_CONSTANT("spaceavail", MADV_SPACEAVAIL);
#endif
}

MODULE = File::Map				PACKAGE = File::Map

PROTOTYPES: DISABLED

BOOT:
    boot(aTHX);

void
_mmap_impl(var, length, prot, flags, fd, offset, utf8 = 0)
	SV* var;
	size_t length;
	int prot;
	int flags;
	int fd;
	Off_t offset;
	int utf8;
	CODE:
		check_new_variable(aTHX_ var);
		
		if (length) {
			ptrdiff_t correction = offset % page_size();
			void* address;
			struct mmap_info* magical;
			if (length > ULONG_MAX - correction)
				real_croak_pv(aTHX_ "Can't map: length + offset overflows");
			address = do_mapping(aTHX_ length + correction, prot, flags, fd, offset - correction);
			
			magical = initialize_mmap_info(aTHX_ address, length, correction, flags);
			reset_var(var, magical);
			add_magic(aTHX_ var, magical, &mmap_table, prot & PROT_WRITE, utf8);
		}
		else {
			struct mmap_info* magical;
			if (!is_mappable(fd)) {
				errno = EACCES;
				die_sys("Could not map: %s");
			}
			sv_setpvn(var, "", 0);

			magical = initialize_mmap_info(aTHX_ SvPV_nolen(var), 0, 0, flags);
			add_magic(aTHX_ var, magical, &empty_table, prot & PROT_WRITE, utf8);
		}

int
_protection_value(mode)
	SV* mode;
	CODE:
		RETVAL = protection_value(mode, FALSE);
	OUTPUT:
		RETVAL

void
sync(var, sync = YES)
	SV* var;
	SV* sync;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "sync");
	CODE:
		IGNORE_EMPTY_MAP(info);
		if (SvREADONLY(var) && ckWARN(WARN_IO))
			Perl_warn(aTHX_ "Syncing a readonly map makes no sense");
		if (msync(info->real_address, info->real_length, SvTRUE(sync) ? MS_SYNC : MS_ASYNC ) == -1)
			die_sys("Could not sync: %s");

#ifdef __linux__
void
remap(var, new_size)
	SV* var;
	size_t new_size;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "remap");
		ptrdiff_t correction = info->real_length - info->fake_length;
		void* new_address;
	CODE:
#ifdef USE_ITHREADS
		if (info->count != 1)
			Perl_croak(aTHX_ "Can't remap a shared mapping");
#endif
		if (EMPTY_MAP(info))
			Perl_croak(aTHX_ "Can't remap empty map"); /* XXX */
		if (new_size == 0)
			Perl_croak(aTHX_ "Can't remap to zero");
		if ((info->flags & (MAP_ANONYMOUS|MAP_SHARED)) == (MAP_ANONYMOUS|MAP_SHARED))
			Perl_croak(aTHX_ "Can't remap a shared anonymous mapping");
		if ((new_address = mremap(info->real_address, info->real_length, new_size + correction, MREMAP_MAYMOVE)) == MAP_FAILED)
			die_sys("Could not remap: %s");
		set_mmap_info(info, new_address, new_size, correction);
		reset_var(var, info);

#endif /* __linux__ */

void
unmap(var)
	SV* var;
	CODE: 
		get_mmap_magic(aTHX_ var, "unmap");
		sv_unmagic(var, PERL_MAGIC_uvar);

void
pin(var)
	SV* var;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "pin");
	CODE:
#ifndef VMS
		IGNORE_EMPTY_MAP(info);
		if (mlock(info->real_address, info->real_length) == -1)
			die_sys("Could not pin: %s");
#else
		Perl_croak(aTHX_ "pin not implemented on VMS");
#endif

void
unpin(var)
	SV* var;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "unpin");
	CODE:
#ifndef VMS
		IGNORE_EMPTY_MAP(info);
		if (munlock(info->real_address, info->real_length) == -1)
			die_sys("Could not unpin: %s");
#else
		Perl_croak(aTHX_ "unpin not implemented on VMS");
#endif

void
advise(var, name)
	SV* var;
	SV* name;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "advise");
		HV* constants = (HV*) *hv_fetch(PL_modglobal, "File::Map::ADVISE_CONSTANTS", 27, 0);
		HE* value = hv_fetch_ent(constants, name, 0, 0);
	CODE:
		IGNORE_EMPTY_MAP(info);
		if (!value) {
			if (ckWARN(WARN_PORTABLE))
				Perl_warn(aTHX_ "Unknown advice '%s'", SvPV_nolen(name));
		}
		else if (madvise(info->real_address, info->real_length, SvUV(HeVAL(value))) == -1)
			die_sys("Could not advice: %s");

void
protect(var, prot)
	SV* var;
	SV* prot;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "protect");
		int prot_val = protection_value(prot, TRUE);
	CODE:
		if (!EMPTY_MAP(info))
			mprotect(info->real_address, info->real_length, prot_val);
		if (prot_val & PROT_WRITE)
			SvREADONLY_off(var);
		else 
			SvREADONLY_on(var);

void
lock_map(var)
	SV* var;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "lock_map");
	CODE:
#ifdef USE_ITHREADS
		LEAVE;
		SAVEDESTRUCTOR_X(magic_end, info);
		MUTEX_LOCK(&info->data_mutex);
		info->owner = aTHX;
		ENTER;
#endif

#ifdef USE_ITHREADS
void
wait_until(block, var)
	SV* block;
	SV* var;
	PROTOTYPE: &@
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "wait_until");
	PPCODE:
		if (info->owner != aTHX)
			Perl_croak(aTHX_ "Trying to wait on an unlocked map");
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
	SV* var;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "notify");
	CODE:
		if (info->owner != aTHX)
			Perl_croak(aTHX_ "Trying to notify on an unlocked map");
		COND_SIGNAL(&info->cond);

void
broadcast(var)
	SV* var;
	PREINIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "broadcast");
	CODE:
		if (info->owner != aTHX)
			Perl_croak(aTHX_ "Trying to broadcast on an unlocked map");
		COND_BROADCAST(&info->cond);

#endif /* USE ITHREADS */
