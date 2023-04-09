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

#include <assert.h>
#include "mmap-compat.c"

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define PERL_NO_GET_CONTEXT
#define PERL_REENTR_API 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "perliol.h"
#define NEED_mg_findext
#define NEED_sv_unmagicext
#include "ppport.h"

#ifndef SvPV_free
#	define SvPV_free(arg) sv_setpvn_mg(arg, NULL, 0);
#endif

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

#define die_sys(format) Perl_croak(aTHX_ format, strerror(errno))

static void reset_var(SV* var, struct mmap_info* info) {
	SvPVX(var) = info->fake_address;
	SvLEN(var) = 0;
	SvCUR(var) = info->fake_length;
	SvPOK_only_UTF8(var);
}

static void S_mmap_fixup(pTHX_ SV* var, struct mmap_info* info, const char* string, STRLEN len) {
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
#define mmap_fixup(var, info, string, len) S_mmap_fixup(aTHX_ var, info, string, len)

static int mmap_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (info->real_length) {
		if (!SvOK(var))
			mmap_fixup(var, info, NULL, 0);
		else if (!SvPOK(var)) {
			STRLEN len;
			const char* string = SvPV(var, len);
			mmap_fixup(var, info, string, len);
		}
		else if (SvPVX(var) != info->fake_address)
			mmap_fixup(var, info, SvPVX(var), SvCUR(var));
		else {
			if (ckWARN(WARN_SUBSTR) && SvCUR(var) != info->fake_length) {
				Perl_warn(aTHX_ "Writing directly to a memory mapped file is not recommended");
				SvCUR(var) = info->fake_length;
			}
			SvPOK_only_UTF8(var);
		}
	}
	else {
		if (!SvPOK(var) || sv_len(var) != 0) {
			sv_setpvn(var, "", 0);
			if (ckWARN(WARN_SUBSTR))
				Perl_warn(aTHX_ "Can't overwrite an empty map");
		}
		SvPOK_only_UTF8(var);
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
		if (info->real_length && munmap(info->real_address, info->real_length) == -1)
			die_sys("Could not unmap: %s");
		COND_DESTROY(&info->cond);
		MUTEX_DESTROY(&info->data_mutex);
		MUTEX_UNLOCK(&info->count_mutex);
		MUTEX_DESTROY(&info->count_mutex);
		PerlMemShared_free(info);
	}
	else {
		if (info->real_length && msync(info->real_address, info->real_length, MS_ASYNC) == -1)
			die_sys("Could not sync: %s");
		MUTEX_UNLOCK(&info->count_mutex);
	}
#else
	if (info->real_length && munmap(info->real_address, info->real_length) == -1)
		die_sys("Could not unmap: %s");
	PerlMemShared_free(info);
#endif 
	SvREADONLY_off(var);
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

static const MGVTBL mmap_table  = { 0, mmap_write, 0, mmap_clear, mmap_free, 0, mmap_dup mmap_local_tail };

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
	if (SvMAGICAL(var) && mg_findext(var, PERL_MAGIC_ext, &mmap_table))
		sv_unmagicext(var, PERL_MAGIC_ext, (MGVTBL*)&mmap_table);
	if (SvROK(var))
		sv_unref_flags(var, SV_IMMEDIATE_UNREF);
	if (SvNIOK(var))
		SvNIOK_off(var);
	if (SvPOK(var)) 
		SvPV_free(var);
	SvUPGRADE(var, SVt_PVMG);
}

static void* do_mapping(pTHX_ size_t length, int prot, int flags, int fd, Off_t offset) {
	void* address;
	address = mmap(0, length, prot, flags | MAP_VARIABLE, fd, offset);
	if (address == MAP_FAILED)
		die_sys("Could not map: %s");
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

static void add_magic(pTHX_ SV* var, struct mmap_info* magical, int writable, int utf8) {
	MAGIC* magic = sv_magicext(var, NULL, PERL_MAGIC_ext, &mmap_table, (const char*) magical, 0);
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
	return Fstat(fd, &info) == 0 && (S_ISREG(info.st_mode) || S_ISBLK(info.st_mode) || S_ISCHR(info.st_mode));
}

#define is_mappable(fd) _is_mappable(aTHX_ fd)

static struct mmap_info* S_get_mmap_magic(pTHX_ SV* var, const char* funcname) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_findext(var, PERL_MAGIC_ext, &mmap_table)) == NULL)
		Perl_croak(aTHX_ "Could not %s: this variable is not memory mapped", funcname);
	return (struct mmap_info*) magic->mg_ptr;
}
#define get_mmap_magic(var, funcname) S_get_mmap_magic(aTHX_ var, funcname)

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

static int S_protection_pvn(pTHX_ const char* mode, size_t mode_len) {
	int i;
	for (i = 0; i < sizeof prots / sizeof *prots; ++i) {
		if (prots[i].length == mode_len && strnEQ(mode, prots[i].key, mode_len))
			return prots[i].value;
	}
	Perl_croak(aTHX_ "No such mode '%s' known", mode);
}
#define protection_pvn(mode, mode_len) S_protection_pvn(aTHX_ mode, mode_len)

static int S_protection_sv(pTHX_ SV* mode_sv) {
	STRLEN mode_len;
	const char* mode = SvPV(mode_sv, mode_len);
	const char* end = memchr(mode, ':', mode_len);
	return protection_pvn(mode, end ? end - mode : mode_len);
}
#define protection_sv(mode) S_protection_sv(aTHX_ mode)

#define MAP_CONSTANT(cons) newCONSTSUB(stash, #cons, newSVuv(cons))
#define ADVISE_CONSTANT(key, value) hv_store(advise_constants, key, sizeof key - 1, newSVuv(value), 0)

#define EMPTY_MAP(info) ((info)->real_length == 0)

static void S_boot(pTHX) {
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
#define boot() S_boot(aTHX)

#if PTRSIZE == 8 && (defined(WIN32) || defined(__CYGWIN__))
#ifndef ULLONG_MAX
#define PTR_MAX _UI64_MAX /* MS Platform SDK crt */
#else
#define PTR_MAX ULLONG_MAX
#endif
#else
#define PTR_MAX ULONG_MAX
#endif

void S_mmap_impl(pTHX_ SV* var, size_t length, int prot, int flags, int fd, Off_t offset, int utf8) {
	check_new_variable(aTHX_ var);

	ptrdiff_t correction = offset % page_size();
	void* address;
	struct mmap_info* magical;
	if (length > PTR_MAX - correction)
		Perl_croak(aTHX_ "can't map: length + offset overflows");

	if (length)
		address = do_mapping(aTHX_ length + correction, prot, flags, fd, offset - correction);
	else {
		if (!is_mappable(fd)) {
			errno = EACCES;
			die_sys("Could not map: %s");
		}
		address = "";
		correction = 0;
	}

	magical = initialize_mmap_info(aTHX_ address, length, correction, flags);
	reset_var(var, magical);
	SvSETMAGIC(var);
	add_magic(aTHX_ var, magical, prot & PROT_WRITE, utf8);
}
#define mmap_impl(var, length, prot, flags, fd, offset, utf8) S_mmap_impl(aTHX_ var, length, prot, flags, fd, offset, utf8)

static const map mappable = {
	{ STR_WITH_LEN("unix"), 1 },
	{ STR_WITH_LEN("perlio"), 1 },
	{ STR_WITH_LEN("crlf"), 1 },
	{ STR_WITH_LEN("stdio"), 1 },
	{ STR_WITH_LEN("flock"), 1 },
	{ STR_WITH_LEN("creat"), 1 },
	{ STR_WITH_LEN("mmap"), 1 },
};

static int S_map_get(pTHX_ const map table, size_t table_size, const char* name, int fallback) {
	int i;
	for (i = 0; i < table_size; ++i) {
		if (strEQ(name, table[i].key))
			return table[i].value;
	}
	return fallback;
}
#define map_get(table, name, default) S_map_get(aTHX_ table, sizeof table / sizeof *table, name, default)

int S_check_layers(pTHX_ PerlIO* fh) {
	PerlIO* current;
	if (PerlIO_fileno(fh) < 0)
		Perl_croak(aTHX_ "Can't map fake filehandle");
	for (current = fh; *current; current = PerlIONext(current)) {
		if (!map_get(mappable, (*current)->tab->name, 0) || (*current)->flags & PERLIO_F_CRLF)
			Perl_croak(aTHX_ "Shouldn't map non-binary filehandle");
	}
	return (*fh)->flags & PERLIO_F_UTF8;
}
#define check_layers(fh) S_check_layers(aTHX_ fh)

size_t S_get_length(pTHX_ PerlIO* fh, Off_t offset, SV* length_sv) {
	Stat_t info;
	Fstat(PerlIO_fileno(fh), &info);
	size_t length = SvOK(length_sv) ? SvIV(length_sv) : info.st_size - offset;
	size_t end = offset + length;
	if (offset < 0 || end > info.st_size && !S_ISCHR(info.st_mode))
		Perl_croak(aTHX_ "Window (%ld,%lu) is outside the file", offset, length);
	return length;
}
#define get_length(fh, offset, length) S_get_length(aTHX_ fh, offset, length)

#define READONLY sv_2mortal(newSVpvs("<"))
#define undef &PL_sv_undef

void S_map_handle(pTHX_ SV* var, PerlIO* fh, SV* mode, Off_t offset, SV* length_sv) {
	int utf8 = check_layers(fh);
	size_t length = get_length(fh, offset, length_sv);
	mmap_impl(var, length, protection_sv(mode), MAP_SHARED | MAP_FILE, PerlIO_fileno(fh), offset, utf8);
}
#define map_handle(var, fh, mode, offset, length) S_map_handle(aTHX_ var, fh, mode, offset, length)

void S_map_file(pTHX_ SV* var, SV* filename, SV* mode, Off_t offset, SV* length_sv) {
	STRLEN mode_len;
	const char* mode_raw = SvPV(mode, mode_len);
	if (memchr(mode_raw, ':', mode_len) == NULL) {
		SV* newmode = sv_2mortal(newSVsv(mode));
		sv_catpvs(newmode, ":raw");
		mode_raw = SvPV(newmode, mode_len);
	}
	GV* gv = MUTABLE_GV(sv_2mortal(newSV_type(SVt_NULL)));
	gv_init_pvn(gv, CopSTASH(PL_curcop),  "__ANONIO__", 10, GV_ADDMULTI);
	if (!do_openn(gv, mode_raw, mode_len, 0, 0, 0, NULL, &filename, 1))
		Perl_croak(aTHX_ "Couldn't open file %s: %s", SvPV_nolen(filename), strerror(errno));
	map_handle(var, IoIFP(GvIO(gv)), mode, offset, length_sv);
}
#define map_file(var, filename, mode, offset, length) S_map_file(aTHX_ var, filename, mode, offset, length)

static const map flags = {
	{ STR_WITH_LEN("shared") , MAP_SHARED },
	{ STR_WITH_LEN("private"), MAP_PRIVATE },
};

void S_map_anonymous(pTHX_ SV* var, size_t length, const char* flag_name) {
	int flag = map_get(flags, flag_name, -1);
	if (flag == -1)
		Perl_croak(aTHX_ "No such flag '%s'", flag_name);
	if (length == 0)
		Perl_croak(aTHX_ "Zero length specified for anonymous map");
	mmap_impl(var, length, PROT_READ | PROT_WRITE, flag | MAP_ANONYMOUS, -1, 0, 0);
}
#define map_anonymous(var, length, flag_name) S_map_anonymous(aTHX_ var, length, flag_name)

void S_sys_map(pTHX_ SV* var, size_t length, int protection, int flags, SV* fh, Off_t offset) {
	if (flags & MAP_ANONYMOUS)
		mmap_impl(var, length, protection, flags, -1, offset, 0);
	else {
		PerlIO* pio = IoIFP(sv_2io(fh)); // XXX error check
		int utf8 = check_layers(pio);
		int fd = PerlIO_fileno(pio);
		mmap_impl(var, length, protection, flags, fd, offset, utf8);
	}
}
#define sys_map(var, length, protection, flags, fh, offset) S_sys_map(aTHX_ var, length, protection, flags, fh, offset)

void S_sync(pTHX_ SV* var, bool sync) {
	struct mmap_info* info = get_mmap_magic(var, "sync");
	if (EMPTY_MAP(info))
		return;
	if (SvREADONLY(var) && ckWARN(WARN_IO))
		Perl_warn(aTHX_ "Syncing a readonly map makes no sense");
	if (msync(info->real_address, info->real_length, sync ? MS_SYNC : MS_ASYNC ) == -1)
		die_sys("Could not sync: %s");
}
#define sync(var, sync) S_sync(aTHX_ var, sync)

#ifdef __linux__
void S_remap(pTHX_ SV* var, size_t new_size) {
	struct mmap_info* info = get_mmap_magic(var, "remap");
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
}
#define remap(var, new_size) S_remap(aTHX_ var, new_size)
#endif

void S_unmap(pTHX_ SV* var) {
	get_mmap_magic(var, "unmap");
	sv_unmagicext(var, PERL_MAGIC_ext, (MGVTBL*)&mmap_table);
}
#define unmap(var) S_unmap(aTHX_ var)

void S_pin(pTHX_ struct mmap_info* info) {
#ifndef VMS
	if (EMPTY_MAP(info))
		return;
	if (mlock(info->real_address, info->real_length) == -1)
		die_sys("Could not pin: %s");
#else
	Perl_croak(aTHX_ "pin not implemented on VMS");
#endif
}
#define pin(var) S_pin(aTHX_ var)

void S_unpin(pTHX_ struct mmap_info* info) {
#ifndef VMS
	if (EMPTY_MAP(info))
		return;
	if (munlock(info->real_address, info->real_length) == -1)
		die_sys("Could not unpin: %s");
#else
	Perl_croak(aTHX_ "unpin not implemented on VMS");
#endif
}
#define unpin(var) S_unpin(aTHX_ var)

void S_advise(pTHX_ struct mmap_info* info, SV* name) {
	HV* constants = (HV*) *hv_fetch(PL_modglobal, "File::Map::ADVISE_CONSTANTS", 27, 0);
	HE* value = hv_fetch_ent(constants, name, 0, 0);

	if (EMPTY_MAP(info))
		return;
	if (!value) {
		if (ckWARN(WARN_PORTABLE))
			Perl_warn(aTHX_ "Unknown advice '%s'", SvPV_nolen(name));
	}
	else if (madvise(info->real_address, info->real_length, SvUV(HeVAL(value))) == -1)
		die_sys("Could not advice: %s");
}
#define advise(var, name) S_advise(aTHX_ var, name)

void S_protect(pTHX_ SV* var, SV* prot) {
	struct mmap_info* info = get_mmap_magic(var, "protect");
	int prot_val = SvIOK(prot) ? SvIV(prot) : protection_sv(prot);
	if (!EMPTY_MAP(info))
		mprotect(info->real_address, info->real_length, prot_val);
	if (prot_val & PROT_WRITE)
		SvREADONLY_off(var);
	else
		SvREADONLY_on(var);
}
#define protect(var, prot) S_protect(aTHX_ var, prot)

void S_lock_map(pTHX_ struct mmap_info* info) {
#ifdef USE_ITHREADS
	LEAVE;
	SAVEDESTRUCTOR_X(magic_end, info);
	MUTEX_LOCK(&info->data_mutex);
	info->owner = aTHX;
	ENTER;
#endif
}
#define lock_map(var) S_lock_map(aTHX_ var)

#ifdef USE_ITHREADS
SV* S_wait_until(pTHX_ SV* block, SV* var) {
	struct mmap_info* info = get_mmap_magic(var, "wait_until");
	if (info->owner != aTHX)
		Perl_croak(aTHX_ "Trying to wait on an unlocked map");
	SAVESPTR(DEFSV);
	DEFSV = var;
	dSP;
	while (1) {
		PUSHMARK(SP);
		call_sv(block, G_SCALAR | G_NOARGS);
		SPAGAIN;
		SV* result = POPs;
		if (SvTRUE(result))
			return SvREFCNT_inc(result);
		COND_WAIT(&info->cond, &info->data_mutex);
	}
}
#define wait_until(block, var) S_wait_until(aTHX_ block, var)

void S_notify(pTHX_ struct mmap_info* info) {
	if (info->owner != aTHX)
		Perl_croak(aTHX_ "Trying to notify on an unlocked map");
	COND_SIGNAL(&info->cond);
}
#define notify(var) S_notify(aTHX_ var)

void S_broadcast(pTHX_ struct mmap_info* info) {
	if (info->owner != aTHX)
		Perl_croak(aTHX_ "Trying to broadcast on an unlocked map");
	COND_BROADCAST(&info->cond);
}
#define broadcast(var) S_broadcast(aTHX_ var)
#endif

MODULE = File::Map				PACKAGE = File::Map

PROTOTYPES: DISABLED

BOOT:
    boot();

void map_file(SV* var, SV* filename, SV* mode = READONLY, Off_t offset = 0, SV* length = undef)

void map_handle(SV* var, PerlIO* fh, SV* mode = READONLY, Off_t offset = 0, SV* length = undef)

void map_anonymous(SV* var, size_t length, const char* flag_name = "shared")

void sys_map(SV* var, size_t length, int protection, int flags, SV* fh = undef, Off_t offset = 0)

void sync(SV* var, bool sync = TRUE)

#ifdef __linux__
void remap(SV* var, size_t new_size)

#endif

void unmap(SV* var)

void pin(struct mmap_info* var)

void unpin(struct mmap_info* var)

void advise(struct mmap_info* var, SV* name)

void protect(SV* var, SV* prot)

void lock_map(struct mmap_info* var)

#ifdef USE_ITHREADS
SV* wait_until(SV* block, SV* var)
	PROTOTYPE: &@

void notify(struct mmap_info* var)

void broadcast(struct mmap_info* var)

#endif /* USE ITHREADS */
