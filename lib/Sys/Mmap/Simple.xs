#include <assert.h>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#define MAP_ANONYMOUS 0
#define ANONYMOUS_HANDLE INVALID_HANDLE_VALUE
typedef HANDLE handle_t;
#else
#include <sys/types.h>
#include <sys/mman.h>
#define ANONYMOUS_HANDLE -1
typedef int handle_t;
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define MMAP_MAGIC_NUMBER 0x4c54

struct mmap_info {
	void* address;
	size_t length;
#ifdef USE_ITHREADS
	perl_mutex count_mutex;
	perl_mutex data_mutex;
	perl_cond cond;
	int count;
#endif
};

#ifdef WIN32
static void croak_sys(pTHX_ const char* format) {
	LPTSTR message;
	DWORD last_error = GetLastError(); 

	DWORD format_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	int length = FormatMessage(format_flags, NULL, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&message, 0, NULL);
	if (message[length - 2] == '\r')
		message[length - 2] =  '\0';

	Perl_croak(aTHX_ format, message);

	LocalFree(message);
}
#define munmap(address, length) ( UnmapViewOfFile(address) ? 0 : -1 )
#define msync(address, length, flags) ( FlushViewOfFile(address, length) ? 0 : -1 ) 
#else
static void croak_sys(pTHX_ const char* format) {
	Perl_croak(aTHX_ format, strerror(errno));
}
#endif

static int mmap_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (SvTYPE(var) < SVt_PV)
		sv_upgrade(var, SVt_PV);
	if (SvPVX(var) != info->address) {
		if (ckWARN(WARN_SUBSTR))
			Perl_warn(aTHX_ "Writing directly to a to a memory mapped file is not recommended");

		Copy(SvPVX(var), info->address, MIN(SvLEN(var), info->length), char);
		SvPV_free(var);
		SvPVX(var) = info->address;
		SvLEN(var) = 0;
		SvCUR(var) = info->length;
		SvPOK_only(var);
	}
	return 0;
}

static U32 mmap_length(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	return info->length;
}

static int mmap_clear(pTHX_ SV* var, MAGIC* magic) {
	if (ckWARN(WARN_SUBSTR))
		Perl_warn(aTHX_ "Clearing a memory mapped file?");
	return 0;
}

static int mmap_free(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	int count;
#ifdef USE_ITHREADS
	MUTEX_LOCK(&info->count_mutex);
	if (--info->count == 0) {
		if (munmap(info->address, info->length) == -1)
			croak_sys(aTHX_ "Could not munmap: %s");
		COND_DESTROY(&info->cond);
		MUTEX_DESTROY(&info->data_mutex);
		MUTEX_UNLOCK(&info->count_mutex);
		MUTEX_DESTROY(&info->count_mutex);
		Safefree(info);
	}
	else {
		if (msync(info->address, info->length, MS_ASYNC) == -1)
			croak_sys(aTHX_ "Could not msync: %s");
		MUTEX_UNLOCK(&info->count_mutex);
	}
#else
	if (munmap(info->address, info->length) == -1)
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
#define TABLE_TAIL ,0, mmap_dup
#else
#define TABLE_TAIL 
#endif

static const MGVTBL mmap_read_table  = { 0, 0,          mmap_length, mmap_clear, mmap_free TABLE_TAIL };
static const MGVTBL mmap_write_table = { 0, mmap_write, mmap_length, mmap_clear, mmap_free TABLE_TAIL };

static SV* check_new_variable(pTHX_ SV* var_ref) {
	SV* var = SvRV(var_ref);
	if (SvTYPE(var) > SVt_PVMG && SvTYPE(var) != SVt_PVLV)
		Perl_croak(aTHX_ "Trying to map into a nonscalar!\n");
	if (SvMAGICAL(var) && mg_find(var, PERL_MAGIC_uvar))
		sv_unmagic(var, PERL_MAGIC_uvar);
	if (SvPOK(var)) 
		SvPV_free(var);
	sv_upgrade(var, SVt_PV);
	return var;
}

static void* do_mapping(pTHX_ size_t length, int writable, int flags, int fd) {
	void* address;
#ifdef WIN32
	int prot = writable ? PAGE_READWRITE | SEC_COMMIT: PAGE_READONLY | SEC_COMMIT;
	HANDLE mapping = CreateFileMapping(_get_osfhandle(fd), NULL, prot, 0, length, NULL);
	if (mapping == NULL)
		croak_sys(aTHX_ "Could not mmap: %s\n");
	address = MapViewOfFile(mapping, writable ? FILE_MAP_WRITE : FILE_MAP_READ, 0, 0, length);
	CloseHandle(mapping);
	if (address == NULL)
#else
	int prot = writable ? PROT_READ | PROT_WRITE : PROT_READ;
	address = mmap(0, length, prot, flags | MAP_SHARED, fd, 0);
	if (address == MAP_FAILED)
#endif
		croak_sys(aTHX_ "Could not mmap: %s\n");
	return address;
}

static struct mmap_info* initialize_mmap_info(void* address, size_t length) {
	struct mmap_info* magical;
	New(0, magical, 1, struct mmap_info);
	magical->address = address;
	magical->length = length;
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

static void mmap_impl(pTHX_ SV* var_ref, size_t length, int writable, int flags, handle_t fd) {
	SV* var = check_new_variable(aTHX_ var_ref);
	void* address = do_mapping(aTHX_ length, writable, flags, fd);
	struct mmap_info* magical = initialize_mmap_info(address, length);

	SvPVX(var) = address;
	SvLEN(var) = 0;
	SvCUR(var) = length;
	SvPOK_only(var);

	add_magic(aTHX_ var, magical, writable);
}

static struct mmap_info* get_mmap_magic(pTHX_ SV* var) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_find(var, PERL_MAGIC_uvar)) == NULL ||  magic->mg_private != MMAP_MAGIC_NUMBER)
		Perl_croak(aTHX_ "This variable is not memory mapped");
	return (struct mmap_info*) magic->mg_ptr;
}

MODULE = Sys::Mmap::Simple				PACKAGE = Sys::Mmap::Simple

PROTOTYPES: DISABLED

SV*
_mmap_impl(var_ref, length, writable, fd)
	SV* var_ref;
	size_t length;
	int writable;
	int fd;
	CODE:
		mmap_impl(aTHX_ var_ref, length, writable, 0, fd);
		ST(0) = &PL_sv_yes;

SV*
map_anonymous(var_ref, length)
	SV* var_ref;
	size_t length;
	PROTOTYPE: \$@
	CODE:
		if (length == 0)
			Perl_croak(aTHX_ "No length specified for anonymous map");
		mmap_impl(aTHX_ var_ref, length, TRUE, MAP_ANONYMOUS, ANONYMOUS_HANDLE);
		ST(0) = &PL_sv_yes;

SV*
sync(var_ref)
	SV* var_ref;
	PROTOTYPE: \$
	CODE:
		SV* var = SvRV(var_ref);
		struct mmap_info* info = get_mmap_magic(aTHX_ var);
		if (msync(info->address, info->length, MS_SYNC) == -1)
			croak_sys(aTHX_ "Could not msync: %s");
		ST(0) = &PL_sv_yes;

#ifdef __linux__
SV*
remap(var_ref, new_size)
	SV* var_ref;
	size_t new_size;
	PROTOTYPE: \$@
	CODE:
		SV* var = SvRV(var_ref);
		struct mmap_info* info = get_mmap_magic(aTHX_ var);
		if (mremap(info->address, info->length, new_size, 0) == MAP_FAILED)
			croak_sys(aTHX_ "Could not mremap: %s");
		ST(0) = &PL_sv_yes;

#endif /* __linux__ */

SV*
unmap(var_ref)
	SV* var_ref;
	PROTOTYPE: \$
	CODE: 
		SV* var = SvRV(var_ref);
		get_mmap_magic(aTHX_ var);
		sv_unmagic(var, PERL_MAGIC_uvar);
		ST(0) = &PL_sv_yes;

void
locked(code, var_ref)
	SV* code;
	SV* var_ref;
	PROTOTYPE: &\$
	PPCODE:
		SV* var = SvRV(var_ref);
		struct mmap_info* info = get_mmap_magic(aTHX_ var);
		
		SAVESPTR(DEFSV);
		DEFSV = var;
		PUSHMARK(SP);
#ifdef USE_ITHREADS
		MUTEX_LOCK(&info->data_mutex);
		call_sv(code, GIMME_V | G_EVAL);
		MUTEX_UNLOCK(&info->data_mutex);
		SPAGAIN;
		if (SvTRUE(ERRSV))
			Perl_croak(aTHX_ NULL);
#else
		call_sv(code, GIMME_V);
		SPAGAIN;
#endif

#ifdef USE_ITHREADS
void
condition_wait(condition)
	SV* condition;
	PROTOTYPE: &
	PPCODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ DEFSV);
		while (1) {
			PUSHMARK(SP);
			call_sv(condition, G_SCALAR);
			SPAGAIN;
			if (SvTRUE(TOPs))
				break;
			POPs;
			COND_WAIT(&info->cond, &info->data_mutex);
		}

void
condition_signal()
	PROTOTYPE:
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ DEFSV);
		COND_SIGNAL(&info->cond);

void
condition_broadcast()
	PROTOTYPE:
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ DEFSV);
		COND_BROADCAST(&info->cond);

#endif /* USE ITHREADS */
