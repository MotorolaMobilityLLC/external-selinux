/*
 * The majority of this code is from Android's
 * external/libselinux/src/android.c and upstream
 * selinux/policycoreutils/setfiles/restore.c
 *
 * See selinux_restorecon(3) for details.
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <linux/magic.h>
#include <libgen.h>
#include <syslog.h>
#include <assert.h>

#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>

#include "callbacks.h"
#include "selinux_internal.h"

#define RESTORECON_LAST "security.restorecon_last"

#define SYS_PATH "/sys"
#define SYS_PREFIX SYS_PATH "/"

#define STAR_COUNT 1000

static struct selabel_handle *fc_sehandle = NULL;
static unsigned char *fc_digest = NULL;
static size_t fc_digest_len = 0;
static char *rootpath = NULL;
static int rootpathlen;

/* Information on excluded fs and directories. */
struct edir {
	char *directory;
	size_t size;
	/* True if excluded by selinux_restorecon_set_exclude_list(3). */
	bool caller_excluded;
};
#define CALLER_EXCLUDED true
static bool ignore_mounts;
static int exclude_non_seclabel_mounts(void);
static int exclude_count = 0;
static struct edir *exclude_lst = NULL;
static uint64_t fc_count = 0;	/* Number of files processed so far */
static uint64_t efile_count;	/* Estimated total number of files */

/*
 * If SELINUX_RESTORECON_PROGRESS is set and mass_relabel = true, then
 * output approx % complete, else output * for every STAR_COUNT files
 * processed to stdout.
 */
static bool mass_relabel;

/* restorecon_flags for passing to restorecon_sb() */
struct rest_flags {
	bool nochange;
	bool verbose;
	bool progress;
	bool set_specctx;
	bool add_assoc;
	bool ignore_digest;
	bool recurse;
	bool userealpath;
	bool set_xdev;
	bool abort_on_error;
	bool syslog_changes;
	bool log_matches;
	bool ignore_noent;
};

static void restorecon_init(void)
{
	struct selabel_handle *sehandle = NULL;

	if (!fc_sehandle) {
		sehandle = selinux_restorecon_default_handle();
		selinux_restorecon_set_sehandle(sehandle);
	}

	efile_count = 0;
	if (!ignore_mounts)
		efile_count = exclude_non_seclabel_mounts();
}

static pthread_once_t fc_once = PTHREAD_ONCE_INIT;

/*
 * Manage excluded directories:
 *  remove_exclude() - This removes any conflicting entries as there could be
 *                     a case where a non-seclabel fs is mounted on /foo and
 *                     then a seclabel fs is mounted on top of it.
 *                     However if an entry has been added via
 *                     selinux_restorecon_set_exclude_list(3) do not remove.
 *
 *  add_exclude()    - Add a directory/fs to be excluded from labeling. If it
 *                     has already been added, then ignore.
 *
 *  check_excluded() - Check if directory/fs is to be excluded when relabeling.
 *
 *  file_system_count() - Calculates the the number of files to be processed.
 *                        The count is only used if SELINUX_RESTORECON_PROGRESS
 *                        is set and a mass relabel is requested.
 *
 *  exclude_non_seclabel_mounts() - Reads /proc/mounts to determine what
 *                                  non-seclabel mounts to exclude from
 *                                  relabeling. restorecon_init() will not
 *                                  call this function if the
 *                                  SELINUX_RESTORECON_IGNORE_MOUNTS
 *                                  flag is set.
 *                                  Setting SELINUX_RESTORECON_IGNORE_MOUNTS
 *                                  is useful where there is a non-seclabel fs
 *                                  mounted on /foo and then a seclabel fs is
 *                                  mounted on a directory below this.
 */
static void remove_exclude(const char *directory)
{
	int i;

	for (i = 0; i < exclude_count; i++) {
		if (strcmp(directory, exclude_lst[i].directory) == 0 &&
					!exclude_lst[i].caller_excluded) {
			free(exclude_lst[i].directory);
			if (i != exclude_count - 1)
				exclude_lst[i] = exclude_lst[exclude_count - 1];
			exclude_count--;
			return;
		}
	}
}

static int add_exclude(const char *directory, bool who)
{
	struct edir *tmp_list, *current;
	size_t len = 0;
	int i;

	/* Check if already present. */
	for (i = 0; i < exclude_count; i++) {
		if (strcmp(directory, exclude_lst[i].directory) == 0)
			return 0;
	}

	if (directory == NULL || directory[0] != '/') {
		selinux_log(SELINUX_ERROR,
			    "Full path required for exclude: %s.\n",
			    directory);
		errno = EINVAL;
		return -1;
	}

	tmp_list = realloc(exclude_lst,
			   sizeof(struct edir) * (exclude_count + 1));
	if (!tmp_list)
		goto oom;

	exclude_lst = tmp_list;

	len = strlen(directory);
	while (len > 1 && directory[len - 1] == '/')
		len--;

	current = (exclude_lst + exclude_count);

	current->directory = strndup(directory, len);
	if (!current->directory)
		goto oom;

	current->size = len;
	current->caller_excluded = who;
	exclude_count++;
	return 0;

oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	return -1;
}

static int check_excluded(const char *file)
{
	int i;

	for (i = 0; i < exclude_count; i++) {
		if (strncmp(file, exclude_lst[i].directory,
		    exclude_lst[i].size) == 0) {
			if (file[exclude_lst[i].size] == 0 ||
					 file[exclude_lst[i].size] == '/')
				return 1;
		}
	}
	return 0;
}

static int file_system_count(char *name)
{
	struct statvfs statvfs_buf;
	int nfile = 0;

	memset(&statvfs_buf, 0, sizeof(statvfs_buf));
	if (!statvfs(name, &statvfs_buf))
		nfile = statvfs_buf.f_files - statvfs_buf.f_ffree;

	return nfile;
}

/*
 * This is called once when selinux_restorecon() is first called.
 * Searches /proc/mounts for all file systems that do not support extended
 * attributes and adds them to the exclude directory table.  File systems
 * that support security labels have the seclabel option, return
 * approximate total file count.
 */
static int exclude_non_seclabel_mounts(void)
{
	struct utsname uts;
	FILE *fp;
	size_t len;
	ssize_t num;
	int index = 0, found = 0, nfile = 0;
	char *mount_info[4];
	char *buf = NULL, *item;

	/* Check to see if the kernel supports seclabel */
	if (uname(&uts) == 0 && strverscmp(uts.release, "2.6.30") < 0)
		return 0;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return 0;

	while ((num = getline(&buf, &len, fp)) != -1) {
		found = 0;
		index = 0;
		item = strtok(buf, " ");
		while (item != NULL) {
			mount_info[index] = item;
			if (index == 3)
				break;
			index++;
			item = strtok(NULL, " ");
		}
		if (index < 3) {
			selinux_log(SELINUX_ERROR,
				    "/proc/mounts record \"%s\" has incorrect format.\n",
				    buf);
			continue;
		}

		/* Remove pre-existing entry */
		remove_exclude(mount_info[1]);

		item = strtok(mount_info[3], ",");
		while (item != NULL) {
			if (strcmp(item, "seclabel") == 0) {
				found = 1;
				nfile += file_system_count(mount_info[1]);
				break;
			}
			item = strtok(NULL, ",");
		}

		/* Exclude mount points without the seclabel option */
		if (!found) {
			if (add_exclude(mount_info[1], !CALLER_EXCLUDED) &&
			    errno == ENOMEM)
				assert(0);
		}
	}

	free(buf);
	fclose(fp);
	/* return estimated #Files + 5% for directories and hard links */
	return nfile * 1.05;
}

/*
 * Support filespec services filespec_add(), filespec_eval() and
 * filespec_destroy().
 *
 * selinux_restorecon(3) uses filespec services when the
 * SELINUX_RESTORECON_ADD_ASSOC flag is set for adding associations between
 * an inode and a specification.
 */

/*
 * The hash table of associations, hashed by inode number. Chaining is used
 * for collisions, with elements ordered by inode number in each bucket.
 * Each hash bucket has a dummy header.
 */
#define HASH_BITS 16
#define HASH_BUCKETS (1 << HASH_BITS)
#define HASH_MASK (HASH_BUCKETS-1)

/*
 * An association between an inode and a context.
 */
typedef struct file_spec {
	ino_t ino;		/* inode number */
	char *con;		/* matched context */
	char *file;		/* full pathname */
	struct file_spec *next;	/* next association in hash bucket chain */
} file_spec_t;

static file_spec_t *fl_head;

/*
 * Try to add an association between an inode and a context. If there is a
 * different context that matched the inode, then use the first context
 * that matched.
 */
static int filespec_add(ino_t ino, const char *con, const char *file)
{
	file_spec_t *prevfl, *fl;
	int h, ret;
	struct stat64 sb;

	if (!fl_head) {
		fl_head = malloc(sizeof(file_spec_t) * HASH_BUCKETS);
		if (!fl_head)
			goto oom;
		memset(fl_head, 0, sizeof(file_spec_t) * HASH_BUCKETS);
	}

	h = (ino + (ino >> HASH_BITS)) & HASH_MASK;
	for (prevfl = &fl_head[h], fl = fl_head[h].next; fl;
	     prevfl = fl, fl = fl->next) {
		if (ino == fl->ino) {
			ret = lstat64(fl->file, &sb);
			if (ret < 0 || sb.st_ino != ino) {
				freecon(fl->con);
				free(fl->file);
				fl->file = strdup(file);
				if (!fl->file)
					goto oom;
				fl->con = strdup(con);
				if (!fl->con)
					goto oom;
				return 1;
			}

			if (strcmp(fl->con, con) == 0)
				return 1;

			selinux_log(SELINUX_ERROR,
				"conflicting specifications for %s and %s, using %s.\n",
				file, fl->file, fl->con);
			free(fl->file);
			fl->file = strdup(file);
			if (!fl->file)
				goto oom;
			return 1;
		}

		if (ino > fl->ino)
			break;
	}

	fl = malloc(sizeof(file_spec_t));
	if (!fl)
		goto oom;
	fl->ino = ino;
	fl->con = strdup(con);
	if (!fl->con)
		goto oom_freefl;
	fl->file = strdup(file);
	if (!fl->file)
		goto oom_freefl;
	fl->next = prevfl->next;
	prevfl->next = fl;
	return 0;

oom_freefl:
	free(fl);
oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	return -1;
}

/*
 * Evaluate the association hash table distribution.
 */
static void filespec_eval(void)
{
	file_spec_t *fl;
	int h, used, nel, len, longest;

	if (!fl_head)
		return;

	used = 0;
	longest = 0;
	nel = 0;
	for (h = 0; h < HASH_BUCKETS; h++) {
		len = 0;
		for (fl = fl_head[h].next; fl; fl = fl->next)
			len++;
		if (len)
			used++;
		if (len > longest)
			longest = len;
		nel += len;
	}

	selinux_log(SELINUX_INFO,
		     "filespec hash table stats: %d elements, %d/%d buckets used, longest chain length %d\n",
		     nel, used, HASH_BUCKETS, longest);
}

/*
 * Destroy the association hash table.
 */
static void filespec_destroy(void)
{
	file_spec_t *fl, *tmp;
	int h;

	if (!fl_head)
		return;

	for (h = 0; h < HASH_BUCKETS; h++) {
		fl = fl_head[h].next;
		while (fl) {
			tmp = fl;
			fl = fl->next;
			freecon(tmp->con);
			free(tmp->file);
			free(tmp);
		}
		fl_head[h].next = NULL;
	}
	free(fl_head);
	fl_head = NULL;
}

/*
 * Called if SELINUX_RESTORECON_SET_SPECFILE_CTX is not set to check if
 * the type components differ, updating newtypecon if so.
 */
static int compare_types(char *curcon, char *newcon, char **newtypecon)
{
	int types_differ = 0;
	context_t cona;
	context_t conb;
	int rc = 0;

	cona = context_new(curcon);
	if (!cona) {
		rc = -1;
		goto out;
	}
	conb = context_new(newcon);
	if (!conb) {
		context_free(cona);
		rc = -1;
		goto out;
	}

	types_differ = strcmp(context_type_get(cona), context_type_get(conb));
	if (types_differ) {
		rc |= context_user_set(conb, context_user_get(cona));
		rc |= context_role_set(conb, context_role_get(cona));
		rc |= context_range_set(conb, context_range_get(cona));
		if (!rc) {
			*newtypecon = strdup(context_str(conb));
			if (!*newtypecon) {
				rc = -1;
				goto err;
			}
		}
	}

err:
	context_free(cona);
	context_free(conb);
out:
	return rc;
}

static int restorecon_sb(const char *pathname, const struct stat *sb,
			    struct rest_flags *flags)
{
	char *newcon = NULL;
	char *curcon = NULL;
	char *newtypecon = NULL;
	int rc;
	bool updated = false;
	const char *lookup_path = pathname;
	float pc;

	if (rootpath) {
		if (strncmp(rootpath, lookup_path, rootpathlen) != 0) {
			selinux_log(SELINUX_ERROR,
				    "%s is not located in alt_rootpath %s\n",
				    lookup_path, rootpath);
			return -1;
		}
		lookup_path += rootpathlen;
	}

	if (rootpath != NULL && lookup_path[0] == '\0')
		/* this is actually the root dir of the alt root. */
		rc = selabel_lookup_raw(fc_sehandle, &newcon, "/",
						    sb->st_mode);
	else
		rc = selabel_lookup_raw(fc_sehandle, &newcon, lookup_path,
						    sb->st_mode);

	if (rc < 0) {
		if (errno == ENOENT && flags->verbose)
			selinux_log(SELINUX_INFO,
				    "Warning no default label for %s\n",
				    lookup_path);

		return 0; /* no match, but not an error */
	}

	if (flags->progress) {
		fc_count++;
		if (fc_count % STAR_COUNT == 0) {
			if (mass_relabel && efile_count > 0) {
				pc = (fc_count < efile_count) ? (100.0 *
					     fc_count / efile_count) : 100;
				fprintf(stdout, "\r%-.1f%%", (double)pc);
			} else {
				fprintf(stdout, "*");
			}
		fflush(stdout);
		}
	}

	if (flags->add_assoc) {
		rc = filespec_add(sb->st_ino, newcon, pathname);

		if (rc < 0) {
			selinux_log(SELINUX_ERROR,
				    "filespec_add error: %s\n", pathname);
			freecon(newcon);
			return -1;
		}

		if (rc > 0) {
			/* Already an association and it took precedence. */
			freecon(newcon);
			return 0;
		}
	}

	if (flags->log_matches)
		selinux_log(SELINUX_INFO, "%s matched by %s\n",
			    pathname, newcon);

	if (lgetfilecon_raw(pathname, &curcon) < 0) {
		if (errno != ENODATA)
			goto err;

		curcon = NULL;
	}

	if (strcmp(curcon, newcon) != 0) {
		if (!flags->set_specctx && curcon &&
				    (is_context_customizable(curcon) > 0)) {
			if (flags->verbose) {
				selinux_log(SELINUX_INFO,
				 "%s not reset as customized by admin to %s\n",
							    pathname, curcon);
				goto out;
			}
		}

		if (!flags->set_specctx && curcon) {
			/* If types different then update newcon. */
			rc = compare_types(curcon, newcon, &newtypecon);
			if (rc)
				goto err;

			if (newtypecon) {
				freecon(newcon);
				newcon = newtypecon;
			} else {
				goto out;
			}
		}

		if (!flags->nochange) {
			if (lsetfilecon(pathname, newcon) < 0)
				goto err;
			updated = true;
		}

		if (flags->verbose)
			selinux_log(SELINUX_INFO,
				    "%s %s from %s to %s\n",
				    updated ? "Relabeled" : "Would relabel",
				    pathname, curcon, newcon);

		if (flags->syslog_changes && !flags->nochange) {
			if (curcon)
				syslog(LOG_INFO,
					    "relabeling %s from %s to %s\n",
					    pathname, curcon, newcon);
			else
				syslog(LOG_INFO, "labeling %s to %s\n",
					    pathname, newcon);
		}
	}

out:
	rc = 0;
out1:
	freecon(curcon);
	freecon(newcon);
	return rc;
err:
	selinux_log(SELINUX_ERROR,
		    "Could not set context for %s:  %s\n",
		    pathname, strerror(errno));
	rc = -1;
	goto out1;
}

/*
 * Public API
 */

/* selinux_restorecon(3) - Main function that is responsible for labeling */
int selinux_restorecon(const char *pathname_orig,
				    unsigned int restorecon_flags)
{
	struct rest_flags flags;

	flags.ignore_digest = (restorecon_flags &
		    SELINUX_RESTORECON_IGNORE_DIGEST) ? true : false;
	flags.nochange = (restorecon_flags &
		    SELINUX_RESTORECON_NOCHANGE) ? true : false;
	flags.verbose = (restorecon_flags &
		    SELINUX_RESTORECON_VERBOSE) ? true : false;
	flags.progress = (restorecon_flags &
		    SELINUX_RESTORECON_PROGRESS) ? true : false;
	flags.recurse = (restorecon_flags &
		    SELINUX_RESTORECON_RECURSE) ? true : false;
	flags.set_specctx = (restorecon_flags &
		    SELINUX_RESTORECON_SET_SPECFILE_CTX) ? true : false;
	flags.userealpath = (restorecon_flags &
		   SELINUX_RESTORECON_REALPATH) ? true : false;
	flags.set_xdev = (restorecon_flags &
		   SELINUX_RESTORECON_XDEV) ? true : false;
	flags.add_assoc = (restorecon_flags &
		   SELINUX_RESTORECON_ADD_ASSOC) ? true : false;
	flags.abort_on_error = (restorecon_flags &
		   SELINUX_RESTORECON_ABORT_ON_ERROR) ? true : false;
	flags.syslog_changes = (restorecon_flags &
		   SELINUX_RESTORECON_SYSLOG_CHANGES) ? true : false;
	flags.log_matches = (restorecon_flags &
		   SELINUX_RESTORECON_LOG_MATCHES) ? true : false;
	flags.ignore_noent = (restorecon_flags &
		   SELINUX_RESTORECON_IGNORE_NOENTRY) ? true : false;
	ignore_mounts = (restorecon_flags &
		   SELINUX_RESTORECON_IGNORE_MOUNTS) ? true : false;

	bool issys;
	bool setrestoreconlast = true; /* TRUE = set xattr RESTORECON_LAST
					* FALSE = don't use xattr */
	struct stat sb;
	struct statfs sfsb;
	FTS *fts;
	FTSENT *ftsent;
	char *pathname = NULL, *pathdnamer = NULL, *pathdname, *pathbname;
	char *paths[2] = { NULL, NULL };
	int fts_flags, error, sverrno;
	char *xattr_value = NULL;
	ssize_t size;
	dev_t dev_num = 0;

	if (flags.verbose && flags.progress)
		flags.verbose = false;

	__selinux_once(fc_once, restorecon_init);

	if (!fc_sehandle)
		return -1;

	if (fc_digest_len) {
		xattr_value = malloc(fc_digest_len);
		if (!xattr_value)
			return -1;
	}

	/*
	 * Convert passed-in pathname to canonical pathname by resolving
	 * realpath of containing dir, then appending last component name.
	 */
	if (flags.userealpath) {
		pathbname = basename((char *)pathname_orig);
		if (!strcmp(pathbname, "/") || !strcmp(pathbname, ".") ||
					    !strcmp(pathbname, "..")) {
			pathname = realpath(pathname_orig, NULL);
			if (!pathname)
				goto realpatherr;
		} else {
			pathdname = dirname((char *)pathname_orig);
			pathdnamer = realpath(pathdname, NULL);
			if (!pathdnamer)
				goto realpatherr;
			if (!strcmp(pathdnamer, "/"))
				error = asprintf(&pathname, "/%s", pathbname);
			else
				error = asprintf(&pathname, "%s/%s",
						    pathdnamer, pathbname);
			if (error < 0)
				goto oom;
		}
	} else {
		pathname = strdup(pathname_orig);
		if (!pathname)
			goto oom;
	}

	paths[0] = pathname;
	issys = (!strcmp(pathname, SYS_PATH) ||
			    !strncmp(pathname, SYS_PREFIX,
			    sizeof(SYS_PREFIX) - 1)) ? true : false;

	if (lstat(pathname, &sb) < 0) {
		if (flags.ignore_noent && errno == ENOENT) {
			free(pathdnamer);
			free(pathname);
			return 0;
		} else {
			selinux_log(SELINUX_ERROR,
				    "lstat(%s) failed: %s\n",
				    pathname, strerror(errno));
			error = -1;
			goto cleanup;
		}
	}

	/* Ignore restoreconlast if not a directory */
	if ((sb.st_mode & S_IFDIR) != S_IFDIR)
		setrestoreconlast = false;

	if (!flags.recurse) {
		if (check_excluded(pathname)) {
			error = 0;
			goto cleanup;
		}

		error = restorecon_sb(pathname, &sb, &flags);
		goto cleanup;
	}

	/* Ignore restoreconlast on /sys */
	if (issys)
		setrestoreconlast = false;

	/* Ignore restoreconlast on in-memory filesystems */
	if (statfs(pathname, &sfsb) == 0) {
		if (sfsb.f_type == RAMFS_MAGIC || sfsb.f_type == TMPFS_MAGIC)
			setrestoreconlast = false;
	}

	if (setrestoreconlast) {
		size = getxattr(pathname, RESTORECON_LAST, xattr_value,
							    fc_digest_len);

		if (!flags.ignore_digest && (size_t)size == fc_digest_len &&
			    memcmp(fc_digest, xattr_value, fc_digest_len)
								    == 0) {
			selinux_log(SELINUX_INFO,
			    "Skipping restorecon as matching digest on: %s\n",
				    pathname);
			error = 0;
			goto cleanup;
		}
	}

	mass_relabel = false;
	if (!strcmp(pathname, "/")) {
		mass_relabel = true;
		if (flags.set_xdev && flags.progress)
			/*
			 * Need to recalculate to get accurate % complete
			 * as only root device id will be processed.
			 */
			efile_count = file_system_count(pathname);
	}

	if (flags.set_xdev)
		fts_flags = FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV;
	else
		fts_flags = FTS_PHYSICAL | FTS_NOCHDIR;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts)
		goto fts_err;

	ftsent = fts_read(fts);
	if (!ftsent)
		goto fts_err;

	/*
	 * Keep the inode of the first device. This is because the FTS_XDEV
	 * flag tells fts not to descend into directories with different
	 * device numbers, but fts will still give back the actual directory.
	 * By saving the device number of the directory that was passed to
	 * selinux_restorecon() and then skipping all actions on any
	 * directories with a different device number when the FTS_XDEV flag
	 * is set (from http://marc.info/?l=selinux&m=124688830500777&w=2).
	 */
	dev_num = ftsent->fts_statp->st_dev;

	error = 0;
	do {
		/* If the FTS_XDEV flag is set and the device is different */
		if (flags.set_xdev && ftsent->fts_statp->st_dev != dev_num)
			continue;

		switch (ftsent->fts_info) {
		case FTS_DC:
			selinux_log(SELINUX_ERROR,
				    "Directory cycle on %s.\n",
				    ftsent->fts_path);
			errno = ELOOP;
			error = -1;
			goto out;
		case FTS_DP:
			continue;
		case FTS_DNR:
			selinux_log(SELINUX_ERROR,
				    "Could not read %s: %s.\n",
				    ftsent->fts_path,
						  strerror(ftsent->fts_errno));
			fts_set(fts, ftsent, FTS_SKIP);
			continue;
		case FTS_NS:
			selinux_log(SELINUX_ERROR,
				    "Could not stat %s: %s.\n",
				    ftsent->fts_path,
						  strerror(ftsent->fts_errno));
			fts_set(fts, ftsent, FTS_SKIP);
			continue;
		case FTS_ERR:
			selinux_log(SELINUX_ERROR,
				    "Error on %s: %s.\n",
				    ftsent->fts_path,
						  strerror(ftsent->fts_errno));
			fts_set(fts, ftsent, FTS_SKIP);
			continue;
		case FTS_D:
			if (issys && !selabel_partial_match(fc_sehandle,
					    ftsent->fts_path)) {
				fts_set(fts, ftsent, FTS_SKIP);
				continue;
			}

			if (check_excluded(ftsent->fts_path)) {
				fts_set(fts, ftsent, FTS_SKIP);
				continue;
			}
			/* fall through */
		default:
			error |= restorecon_sb(ftsent->fts_path,
					       ftsent->fts_statp, &flags);

			if (error && flags.abort_on_error)
				goto out;
			break;
		}
	} while ((ftsent = fts_read(fts)) != NULL);

	/* Labeling successful. Mark the top level directory as completed. */
	if (setrestoreconlast && !flags.nochange && !error && fc_digest) {
		error = setxattr(pathname, RESTORECON_LAST, fc_digest,
						    fc_digest_len, 0);
		if (!error && flags.verbose)
			selinux_log(SELINUX_INFO,
				   "Updated digest for: %s\n", pathname);
	}

out:
	if (flags.progress) {
		if (mass_relabel)
			fprintf(stdout, "\r100.0%%\n");
		else
			fprintf(stdout, "\n");
	}

	sverrno = errno;
	(void) fts_close(fts);
	errno = sverrno;
cleanup:
	if (flags.add_assoc) {
		if (flags.verbose)
			filespec_eval();
		filespec_destroy();
	}
	free(pathdnamer);
	free(pathname);
	free(xattr_value);
	return error;

oom:
	sverrno = errno;
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	errno = sverrno;
	error = -1;
	goto cleanup;

realpatherr:
	sverrno = errno;
	selinux_log(SELINUX_ERROR,
		    "SELinux: Could not get canonical path for %s restorecon: %s.\n",
		    pathname_orig, strerror(errno));
	errno = sverrno;
	error = -1;
	goto cleanup;

fts_err:
	selinux_log(SELINUX_ERROR,
		    "fts error while labeling %s: %s\n",
		    paths[0], strerror(errno));
	error = -1;
	goto cleanup;
}

/* selinux_restorecon_set_sehandle(3) is called to set the global fc handle */
void selinux_restorecon_set_sehandle(struct selabel_handle *hndl)
{
	char **specfiles;
	size_t num_specfiles;

	fc_sehandle = (struct selabel_handle *) hndl;

	/*
	 * Read digest if requested in selabel_open(3) and set global params.
	 */
	if (selabel_digest(fc_sehandle, &fc_digest, &fc_digest_len,
				   &specfiles, &num_specfiles) < 0) {
		fc_digest = NULL;
		fc_digest_len = 0;
	}
}

/*
 * selinux_restorecon_default_handle(3) is called to set the global restorecon
 * handle by a process if the default params are required.
 */
struct selabel_handle *selinux_restorecon_default_handle(void)
{
	struct selabel_handle *sehandle;

	struct selinux_opt fc_opts[] = {
		{ SELABEL_OPT_DIGEST, (char *)1 }
	};

	sehandle = selabel_open(SELABEL_CTX_FILE, fc_opts, 1);

	if (!sehandle) {
		selinux_log(SELINUX_ERROR,
			    "Error obtaining file context handle: %s\n",
						    strerror(errno));
		return NULL;
	}

	return sehandle;
}

/*
 * selinux_restorecon_set_exclude_list(3) is called to add additional entries
 * to be excluded from labeling checks.
 */
void selinux_restorecon_set_exclude_list(const char **exclude_list)
{
	int i;
	struct stat sb;

	for (i = 0; exclude_list[i]; i++) {
		if (lstat(exclude_list[i], &sb) < 0 && errno != EACCES) {
			selinux_log(SELINUX_ERROR,
				    "lstat error on exclude path \"%s\", %s - ignoring.\n",
				    exclude_list[i], strerror(errno));
			break;
		}
		if (add_exclude(exclude_list[i], CALLER_EXCLUDED) &&
		    errno == ENOMEM)
			assert(0);
	}
}

/* selinux_restorecon_set_alt_rootpath(3) sets an alternate rootpath. */
int selinux_restorecon_set_alt_rootpath(const char *alt_rootpath)
{
	int len;

	/* This should be NULL on first use */
	if (rootpath)
		free(rootpath);

	rootpath = strdup(alt_rootpath);
	if (!rootpath) {
		selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
		return -1;
	}

	/* trim trailing /, if present */
	len = strlen(rootpath);
	while (len && (rootpath[len - 1] == '/'))
		rootpath[--len] = '\0';
	rootpathlen = len;

	return 0;
}
