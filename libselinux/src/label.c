/*
 * Generalized labeling frontend for userspace object managers.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 */

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <selinux/selinux.h>
#include "callbacks.h"
#include "label_internal.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifdef NO_MEDIA_BACKEND
#define CONFIG_MEDIA_BACKEND(fnptr) NULL
#else
#define CONFIG_MEDIA_BACKEND(fnptr) &fnptr
#endif

#ifdef NO_X_BACKEND
#define CONFIG_X_BACKEND(fnptr) NULL
#else
#define CONFIG_X_BACKEND(fnptr) &fnptr
#endif

#ifdef NO_DB_BACKEND
#define CONFIG_DB_BACKEND(fnptr) NULL
#else
#define CONFIG_DB_BACKEND(fnptr) &fnptr
#endif

typedef int (*selabel_initfunc)(struct selabel_handle *rec,
				const struct selinux_opt *opts,
				unsigned nopts);

static selabel_initfunc initfuncs[] = {
	&selabel_file_init,
	CONFIG_MEDIA_BACKEND(selabel_media_init),
	CONFIG_X_BACKEND(selabel_x_init),
	CONFIG_DB_BACKEND(selabel_db_init),
	&selabel_property_init,
};

static void selabel_subs_fini(struct selabel_sub *ptr)
{
	struct selabel_sub *next;

	while (ptr) {
		next = ptr->next;
		free(ptr->src);
		free(ptr->dst);
		free(ptr);
		ptr = next;
	}
}

static char *selabel_sub(struct selabel_sub *ptr, const char *src)
{
	char *dst = NULL;
	int len;

	while (ptr) {
		if (strncmp(src, ptr->src, ptr->slen) == 0 ) {
			if (src[ptr->slen] == '/' || 
			    src[ptr->slen] == 0) {
				if ((src[ptr->slen] == '/') &&
				    (strcmp(ptr->dst, "/") == 0))
					len = ptr->slen + 1;
				else
					len = ptr->slen;
				if (asprintf(&dst, "%s%s", ptr->dst, &src[len]) < 0)
					return NULL;
				return dst;
			}
		}
		ptr = ptr->next;
	}
	return NULL;
}

struct selabel_sub *selabel_subs_init(const char *path,
					    struct selabel_sub *list,
					    struct selabel_digest *digest)
{
	char buf[1024];
	FILE *cfg = fopen(path, "r");
	struct selabel_sub *sub = NULL;
	struct stat sb;

	if (!cfg)
		return list;

	if (fstat(fileno(cfg), &sb) < 0)
		return list;

	while (fgets_unlocked(buf, sizeof(buf) - 1, cfg)) {
		char *ptr = NULL;
		char *src = buf;
		char *dst = NULL;

		while (*src && isspace(*src))
			src++;
		if (src[0] == '#') continue;
		ptr = src;
		while (*ptr && ! isspace(*ptr))
			ptr++;
		*ptr++ = '\0';
		if (! *src) continue;

		dst = ptr;
		while (*dst && isspace(*dst))
			dst++;
		ptr=dst;
		while (*ptr && ! isspace(*ptr))
			ptr++;
		*ptr='\0';
		if (! *dst)
			continue;

		sub = malloc(sizeof(*sub));
		if (! sub)
			goto err;
		memset(sub, 0, sizeof(*sub));

		sub->src=strdup(src);
		if (! sub->src)
			goto err;

		sub->dst=strdup(dst);
		if (! sub->dst)
			goto err;

		sub->slen = strlen(src);
		sub->next = list;
		list = sub;
	}

	if (digest_add_specfile(digest, cfg, NULL, sb.st_size, path) < 0)
		goto err;

out:
	fclose(cfg);
	return list;
err:
	if (sub)
		free(sub->src);
	free(sub);
	goto out;
}

static inline struct selabel_digest *selabel_is_digest_set
				    (const struct selinux_opt *opts,
				    unsigned n,
				    struct selabel_digest *entry)
{
	struct selabel_digest *digest = NULL;

	while (n--) {
		if (opts[n].type == SELABEL_OPT_DIGEST &&
					    opts[n].value == (char *)1) {
			digest = calloc(1, sizeof(*digest));
			if (!digest)
				goto err;

			digest->digest = calloc(1, DIGEST_SPECFILE_SIZE + 1);
			if (!digest->digest)
				goto err;

			digest->specfile_list = calloc(DIGEST_FILES_MAX,
							    sizeof(char *));
			if (!digest->specfile_list)
				goto err;

			entry = digest;
			return entry;
		}
	}
	return NULL;

err:
	free(digest->digest);
	free(digest->specfile_list);
	free(digest);
	return NULL;
}

static void selabel_digest_fini(struct selabel_digest *ptr)
{
	int i;

	free(ptr->digest);
	free(ptr->hashbuf);

	if (ptr->specfile_list) {
		for (i = 0; ptr->specfile_list[i]; i++)
			free(ptr->specfile_list[i]);
		free(ptr->specfile_list);
	}
	free(ptr);
}

/*
 * Validation functions
 */

static inline int selabel_is_validate_set(const struct selinux_opt *opts,
					  unsigned n)
{
	while (n--)
		if (opts[n].type == SELABEL_OPT_VALIDATE)
			return !!opts[n].value;

	return 0;
}

int selabel_validate(struct selabel_handle *rec,
		     struct selabel_lookup_rec *contexts)
{
	int rc = 0;

	if (!rec->validating || contexts->validated)
		goto out;

	rc = selinux_validate(&contexts->ctx_raw);
	if (rc < 0)
		goto out;

	contexts->validated = 1;
out:
	return rc;
}

/* Public API helpers */
static char *selabel_sub_key(struct selabel_handle *rec, const char *key)
{
	char *ptr = NULL;
	char *dptr = NULL;

	ptr = selabel_sub(rec->subs, key);
	if (ptr) {
		dptr = selabel_sub(rec->dist_subs, ptr);
		if (dptr) {
			free(ptr);
			ptr = dptr;
		}
	} else {
		ptr = selabel_sub(rec->dist_subs, key);
	}
	if (ptr)
		return ptr;

	return NULL;
}

static int selabel_fini(struct selabel_handle *rec,
			    struct selabel_lookup_rec *lr,
			    int translating)
{
	if (compat_validate(rec, lr, rec->spec_file, 0))
		return -1;

	if (translating && !lr->ctx_trans &&
	    selinux_raw_to_trans_context(lr->ctx_raw, &lr->ctx_trans))
		return -1;

	return 0;
}

static struct selabel_lookup_rec *
selabel_lookup_common(struct selabel_handle *rec, int translating,
		      const char *key, int type)
{
	struct selabel_lookup_rec *lr;
	char *ptr = NULL;

	if (key == NULL) {
		errno = EINVAL;
		return NULL;
	}

	ptr = selabel_sub_key(rec, key);
	if (ptr) {
		lr = rec->func_lookup(rec, ptr, type);
		free(ptr);
	} else {
		lr = rec->func_lookup(rec, key, type);
	}
	if (!lr)
		return NULL;

	if (selabel_fini(rec, lr, translating))
		return NULL;

	return lr;
}

static struct selabel_lookup_rec *
selabel_lookup_bm_common(struct selabel_handle *rec, int translating,
		      const char *key, int type, const char **aliases)
{
	struct selabel_lookup_rec *lr;
	char *ptr = NULL;

	if (key == NULL) {
		errno = EINVAL;
		return NULL;
	}

	ptr = selabel_sub_key(rec, key);
	if (ptr) {
		lr = rec->func_lookup_best_match(rec, ptr, aliases, type);
		free(ptr);
	} else {
		lr = rec->func_lookup_best_match(rec, key, aliases, type);
	}
	if (!lr)
		return NULL;

	if (selabel_fini(rec, lr, translating))
		return NULL;

	return lr;
}

/*
 * Public API
 */

struct selabel_handle *selabel_open(unsigned int backend,
				    const struct selinux_opt *opts,
				    unsigned nopts)
{
	struct selabel_handle *rec = NULL;

	if (backend >= ARRAY_SIZE(initfuncs)) {
		errno = EINVAL;
		goto out;
	}

	if (!initfuncs[backend]) {
		errno = ENOTSUP;
		goto out;
	}

	rec = (struct selabel_handle *)malloc(sizeof(*rec));
	if (!rec)
		goto out;

	memset(rec, 0, sizeof(*rec));
	rec->backend = backend;
	rec->validating = selabel_is_validate_set(opts, nopts);

	rec->subs = NULL;
	rec->dist_subs = NULL;
	rec->digest = selabel_is_digest_set(opts, nopts, rec->digest);

	if ((*initfuncs[backend])(rec, opts, nopts)) {
		free(rec->spec_file);
		free(rec);
		rec = NULL;
	}

out:
	return rec;
}

int selabel_lookup(struct selabel_handle *rec, char **con,
		   const char *key, int type)
{
	struct selabel_lookup_rec *lr;

	lr = selabel_lookup_common(rec, 1, key, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_trans);
	return *con ? 0 : -1;
}

int selabel_lookup_raw(struct selabel_handle *rec, char **con,
		       const char *key, int type)
{
	struct selabel_lookup_rec *lr;

	lr = selabel_lookup_common(rec, 0, key, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_raw);
	return *con ? 0 : -1;
}

bool selabel_partial_match(struct selabel_handle *rec, const char *key)
{
	char *ptr;
	bool ret;

	if (!rec->func_partial_match) {
		/*
		 * If the label backend does not support partial matching,
		 * then assume a match is possible.
		 */
		return true;
	}

	ptr = selabel_sub_key(rec, key);
	if (ptr) {
		ret = rec->func_partial_match(rec, ptr);
		free(ptr);
	} else {
		ret = rec->func_partial_match(rec, key);
	}

	return ret;
}

int selabel_lookup_best_match(struct selabel_handle *rec, char **con,
			      const char *key, const char **aliases, int type)
{
	struct selabel_lookup_rec *lr;

	if (!rec->func_lookup_best_match) {
		errno = ENOTSUP;
		return -1;
	}

	lr = selabel_lookup_bm_common(rec, 1, key, type, aliases);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_trans);
	return *con ? 0 : -1;
}

int selabel_lookup_best_match_raw(struct selabel_handle *rec, char **con,
			      const char *key, const char **aliases, int type)
{
	struct selabel_lookup_rec *lr;

	if (!rec->func_lookup_best_match) {
		errno = ENOTSUP;
		return -1;
	}

	lr = selabel_lookup_bm_common(rec, 0, key, type, aliases);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_raw);
	return *con ? 0 : -1;
}

enum selabel_cmp_result selabel_cmp(struct selabel_handle *h1,
				    struct selabel_handle *h2)
{
	if (!h1->func_cmp || h1->func_cmp != h2->func_cmp)
		return SELABEL_INCOMPARABLE;

	return h1->func_cmp(h1, h2);
}

int selabel_digest(struct selabel_handle *rec,
				    unsigned char **digest, size_t *digest_len,
				    char ***specfiles, size_t *num_specfiles)
{
	if (!rec->digest) {
		errno = EINVAL;
		return -1;
	}

	*digest = rec->digest->digest;
	*digest_len = DIGEST_SPECFILE_SIZE;
	*specfiles = rec->digest->specfile_list;
	*num_specfiles = rec->digest->specfile_cnt;
	return 0;
}

void selabel_close(struct selabel_handle *rec)
{
	selabel_subs_fini(rec->subs);
	selabel_subs_fini(rec->dist_subs);
	if (rec->digest)
		selabel_digest_fini(rec->digest);
	rec->func_close(rec);
	free(rec->spec_file);
	free(rec);
}

void selabel_stats(struct selabel_handle *rec)
{
	rec->func_stats(rec);
}
