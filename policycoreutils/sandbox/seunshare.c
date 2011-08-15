#define _GNU_SOURCE
#include <signal.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/mount.h>
#include <glob.h>
#include <pwd.h>
#include <sched.h>
#include <libcgroup.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <unistd.h>
#include <stdlib.h>
#include <cap-ng.h>
#include <getopt.h>		/* for getopt_long() form of getopt() */
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <selinux/selinux.h>
#include <selinux/context.h>	/* for context-mangling functions */

#ifdef USE_NLS
#include <locale.h>		/* for setlocale() */
#include <libintl.h>		/* for gettext() */
#define _(msgid) gettext (msgid)
#else
#define _(msgid) (msgid)
#endif

#ifndef MS_REC
#define MS_REC 1<<14
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE 1<<18
#endif

#define BUF_SIZE 1024
#define DEFAULT_PATH "/usr/bin:/bin"
#define USAGE_STRING _("USAGE: seunshare [ -v ] [ -C ] [ -c ] [ -t tmpdir ] [ -h homedir ] [ -Z CONTEXT ] -- executable [args] ")

static int verbose = 0;

static capng_select_t cap_set = CAPNG_SELECT_BOTH;

/**
 * This function will drop all capabilities.
 */
static int drop_caps()
{
	if (capng_have_capabilities(cap_set) == CAPNG_NONE)
		return 0;
	capng_clear(cap_set);
	if (capng_lock() == -1 || capng_apply(cap_set) == -1) {
		fprintf(stderr, _("Failed to drop all capabilities\n"));
		return -1;
	}
	return 0;
}

/**
 * This function will drop all privileges.
 */
static int drop_privs(uid_t uid)
{
	if (drop_caps() == -1 || setresuid(uid, uid, uid) == -1) {
		fprintf(stderr, _("Failed to drop privileges\n"));
		return -1;
	}
	return 0;
}

/**
 * Take care of any signal setup.
 */
static int set_signal_handles(void)
{
	sigset_t empty;

	/* Empty the signal mask in case someone is blocking a signal */
	if (sigemptyset(&empty)) {
		fprintf(stderr, "Unable to obtain empty signal set\n");
		return -1;
	}

	(void)sigprocmask(SIG_SETMASK, &empty, NULL);

	/* Terminate on SIGHUP */
	if (signal(SIGHUP, SIG_DFL) == SIG_ERR) {
		perror("Unable to set SIGHUP handler");
		return -1;
	}

	return 0;
}

#define status_to_retval(status,retval) do { \
	if ((status) == -1) \
		retval = -1; \
	else if (WIFEXITED((status))) \
		retval = WEXITSTATUS((status)); \
	else if (WIFSIGNALED((status))) \
		retval = 128 + WTERMSIG((status)); \
	else \
		retval = -1; \
	} while(0)

/**
 * Spawn external command using system() with dropped privileges.
 * TODO: avoid system() and use exec*() instead
 */
static int spawn_command(const char *cmd, uid_t uid){
	int child;
	int status = -1;

	if (verbose > 1)
		printf("spawn_command: %s\n", cmd);

	child = fork();
	if (child == -1) {
		perror(_("Unable to fork"));
		return status;
	}

	if (child == 0) {
		if (drop_privs(uid) != 0) exit(-1);

		status = system(cmd);
		status_to_retval(status, status);
		exit(status);
	}

	waitpid(child, &status, 0);
	status_to_retval(status, status);
	return status;
}

/**
 * Check file/directory ownership, struct stat * must be passed to the
 * functions.
 */
static int check_owner_uid(uid_t uid, const char *file, struct stat *st) {
	if (S_ISLNK(st->st_mode)) {
		fprintf(stderr, _("Error: %s must not be a symbolic link\n"), file);
		return -1;
	}
	if (st->st_uid != uid) {
		fprintf(stderr, _("Error: %s not owned by UID %d\n"), file, uid);
		return -1;
	}
	return 0;
}

static int check_owner_gid(gid_t gid, const char *file, struct stat *st) {
	if (S_ISLNK(st->st_mode)) {
		fprintf(stderr, _("Error: %s must not be a symbolic link\n"), file);
		return -1;
	}
	if (st->st_gid != gid) {
		fprintf(stderr, _("Error: %s not owned by GID %d\n"), file, gid);
		return -1;
	}
	return 0;
}

#define equal_stats(one,two) \
	((one)->st_dev == (two)->st_dev && (one)->st_ino == (two)->st_ino && \
	 (one)->st_uid == (two)->st_uid && (one)->st_gid == (two)->st_gid && \
	 (one)->st_mode == (two)->st_mode)

/**
 * Sanity check specified directory.  Store stat info for future comparison, or
 * compare with previously saved info to detect replaced directories.
 * Note: This function does not perform owner checks.
 */
static int verify_directory(const char *dir, struct stat *st_in, struct stat *st_out) {
	struct stat sb;

	if (st_out == NULL) st_out = &sb;

	if (lstat(dir, st_out) == -1) {
		fprintf(stderr, _("Failed to stat %s: %s\n"), dir, strerror(errno));
		return -1;
	}
	if (! S_ISDIR(st_out->st_mode)) {
		fprintf(stderr, _("Error: %s is not a directory: %s\n"), dir, strerror(errno));
		return -1;
	}
	if (st_in && !equal_stats(st_in, st_out)) {
		fprintf(stderr, _("Error: %s was replaced by a different directory\n"), dir);
		return -1;
	}

	return 0;
}

/**
 * This function checks to see if the shell is known in /etc/shells.
 * If so, it returns 0. On error or illegal shell, it returns -1.
 */
static int verify_shell(const char *shell_name)
{
	int rc = -1;
	const char *buf;

	if (!(shell_name && shell_name[0]))
		return rc;

	while ((buf = getusershell()) != NULL) {
		/* ignore comments */
		if (*buf == '#')
			continue;

		/* check the shell skipping newline char */
		if (!strcmp(shell_name, buf)) {
			rc = 0;
			break;
		}
	}
	endusershell();
	return rc;
}

/**
 * Mount directory and check that we mounted the right directory.
 */
static int seunshare_mount(const char *src, const char *dst, struct stat *src_st)
{
	int flags = MS_REC;
	int is_tmp = 0;

	if (verbose)
		printf(_("Mounting %s on %s\n"), src, dst);

	if (strcmp("/tmp", dst) == 0) {
		flags = flags | MS_NODEV | MS_NOSUID | MS_NOEXEC;
		is_tmp = 1;
	}

	/* mount directory */
	if (mount(dst, dst,  NULL, MS_BIND | flags, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), dst, dst, strerror(errno));
		return -1;
	}
	if (mount(dst, dst, NULL, MS_PRIVATE | flags, NULL) < 0) {
		fprintf(stderr, _("Failed to make %s private: %s\n"), dst, strerror(errno));
		return -1;
	}
	if (mount(src, dst, NULL, MS_BIND | flags, NULL) < 0) {
		fprintf(stderr, _("Failed to mount %s on %s: %s\n"), src, dst, strerror(errno));
		return -1;
	}

	/* verify whether we mounted what we expected to mount */
	if (verify_directory(dst, src_st, NULL) < 0) return -1;

	/* bind mount /tmp on /var/tmp too */
	if (is_tmp) {
		if (verbose)
			printf(_("Mounting /tmp on /var/tmp\n"));

		if (mount("/var/tmp", "/var/tmp",  NULL, MS_BIND | flags, NULL) < 0) {
			fprintf(stderr, _("Failed to mount /var/tmp on /var/tmp: %s\n"), strerror(errno));
			return -1;
		}
		if (mount("/var/tmp", "/var/tmp", NULL, MS_PRIVATE | flags, NULL) < 0) {
			fprintf(stderr, _("Failed to make /var/tmp private: %s\n"), strerror(errno));
			return -1;
		}
		if (mount("/tmp", "/var/tmp",  NULL, MS_BIND | flags, NULL) < 0) {
			fprintf(stderr, _("Failed to mount /tmp on /var/tmp: %s\n"), strerror(errno));
			return -1;
		}
	}

	return 0;

}

/**
 * Error logging used by cgroups code.
 */
static int sandbox_error(const char *string)
{
	fprintf(stderr, string);
	syslog(LOG_AUTHPRIV | LOG_ALERT, string);
	exit(-1);
}

/**
 * Regular expression match.
 */
static int match(const char *string, char *pattern)
{
	int status;
	regex_t re;
	if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) {
		return 0;
	}
	status = regexec(&re, string, (size_t)0, NULL, 0);
	regfree(&re);
	if (status != 0) {
		return 0;
	}
	return 1;
}

/**
 * Apply cgroups settings from the /etc/sysconfig/sandbox config file.
 */
static int setup_cgroups()
{
	char *cpus = NULL;	/* which CPUs to use */
	char *cgroupname = NULL;/* name for the cgroup */
	char *mem = NULL;	/* string for memory amount to pass to cgroup */
	int64_t memusage = 0;	/* amount of memory to use max (percent) */
	int cpupercentage = 0;  /* what percentage of cpu to allow usage */
	FILE* fp;
	char buf[BUF_SIZE];
	char *tok = NULL;
	int rc = -1;
	char *str = NULL;
	const char* fname = "/etc/sysconfig/sandbox";

	if ((fp = fopen(fname, "rt")) == NULL) {
		fprintf(stderr, "Error opening sandbox config file.");
		return rc;
	}
	while(fgets(buf, BUF_SIZE, fp) != NULL) {
		/* Skip comments */
		if (buf[0] == '#') continue;

		/* Copy the string, ignoring whitespace */
		int len = strlen(buf);
		free(str);
		str = malloc((len + 1) * sizeof(char));
		if (!str)
			goto err;

		int ind = 0;
		int i;
		for (i = 0; i < len; i++) {
			char cur = buf[i];
			if (cur != ' ' && cur != '\t') {
				str[ind] = cur;
				ind++;
			}
		}
		str[ind] = '\0';

		tok = strtok(str, "=\n");
		if (tok != NULL) {
			if (!strcmp(tok, "CPUAFFINITY")) {
				tok = strtok(NULL, "=\n");
				cpus = strdup(tok);
				if (!strcmp(cpus, "ALL")) {
					free(cpus);
					cpus = NULL;
				}
			} else if (!strcmp(tok, "MEMUSAGE")) {
				tok = strtok(NULL, "=\n");
				if (match(tok, "^[0-9]+[kKmMgG%]")) {
					char *ind = strchr(tok, '%');
					if (ind != NULL) {
						*ind = '\0';;
						memusage = atoi(tok);
					} else {
						mem = strdup(tok);
					}
				} else {
					fprintf(stderr, "Error parsing config file.");
					goto err;
				}

			} else if (!strcmp(tok, "CPUUSAGE")) {
				tok = strtok(NULL, "=\n");
				if (match(tok, "^[0-9]+\%")) {
					char* ind = strchr(tok, '%');
					*ind = '\0';
					cpupercentage = atoi(tok);
				} else {
					fprintf(stderr, "Error parsing config file.");
					goto err;
				}
			} else if (!strcmp(tok, "NAME")) {
				tok = strtok(NULL, "=\n");
				cgroupname = strdup(tok);
			} else {
				continue;
			}
		}

	}
	if (mem == NULL) {
		long phypz = sysconf(_SC_PHYS_PAGES);
		long psize = sysconf(_SC_PAGE_SIZE);
		memusage = phypz * psize * (float) memusage / 100.0;
	}

	cgroup_init();

	int64_t current_runtime = 0;
	int64_t current_period = 0 ;
	int64_t current_mem = 0;
	char *curr_cpu_path = NULL;
	char *curr_mem_path = NULL;
	int ret  = cgroup_get_current_controller_path(getpid(), "cpu", &curr_cpu_path);
	if (ret) {
		sandbox_error("Error while trying to get current controller path.\n");
	} else {
		struct cgroup *curr = cgroup_new_cgroup(curr_cpu_path);
		cgroup_get_cgroup(curr);
		cgroup_get_value_int64(cgroup_get_controller(curr, "cpu"), "cpu.rt_runtime_us", &current_runtime);
		cgroup_get_value_int64(cgroup_get_controller(curr, "cpu"), "cpu.rt_period_us", &current_period);
	}

	ret  = cgroup_get_current_controller_path(getpid(), "memory", &curr_mem_path);
	if (ret) {
		sandbox_error("Error while trying to get current controller path.\n");
	} else {
		struct cgroup *curr = cgroup_new_cgroup(curr_mem_path);
		cgroup_get_cgroup(curr);
		cgroup_get_value_int64(cgroup_get_controller(curr, "memory"), "memory.limit_in_bytes", &current_mem);
	}

	if (((float) cpupercentage)  / 100.0> (float)current_runtime / (float) current_period) {
		sandbox_error("CPU usage restricted!\n");
		goto err;
	}

	if (mem == NULL) {
		if (memusage > current_mem) {
			sandbox_error("Attempting to use more memory than allowed!");
			goto err;
		}
	}

	long nprocs = sysconf(_SC_NPROCESSORS_ONLN);

	struct sched_param sp;
	sp.sched_priority = sched_get_priority_min(SCHED_FIFO);
	sched_setscheduler(getpid(), SCHED_FIFO, &sp);
	struct cgroup *sandbox_group = cgroup_new_cgroup(cgroupname);
	cgroup_add_controller(sandbox_group, "memory");
	cgroup_add_controller(sandbox_group, "cpu");

	if (mem == NULL) {
		if (memusage > 0) {
			cgroup_set_value_uint64(cgroup_get_controller(sandbox_group, "memory"), "memory.limit_in_bytes", memusage);
		}
	} else {
		cgroup_set_value_string(cgroup_get_controller(sandbox_group, "memory"), "memory.limit_in_bytes", mem);
	}
	if (cpupercentage > 0) {
		cgroup_set_value_uint64(cgroup_get_controller(sandbox_group, "cpu"), "cpu.rt_runtime_us",
					(float) cpupercentage / 100.0 * 60000);
		cgroup_set_value_uint64(cgroup_get_controller(sandbox_group, "cpu"), "cpu.rt_period_us",60000 * nprocs);
	}
	if (cpus != NULL) {
		cgroup_set_value_string(cgroup_get_controller(sandbox_group, "cpu"), "cgroup.procs",cpus);
	}

	uint64_t allocated_mem;
	if (cgroup_get_value_uint64(cgroup_get_controller(sandbox_group, "memory"), "memory.limit_in_bytes", &allocated_mem) > current_mem) {
		sandbox_error("Attempting to use more memory than allowed!\n");
		goto err;
	}

	rc = cgroup_create_cgroup(sandbox_group, 1);
	if (rc != 0) {
		sandbox_error("Failed to create group.  Ensure that cgconfig service is running. \n");
		goto err;
	}

	cgroup_attach_task(sandbox_group);

	rc = 0;
err:
	fclose(fp);
	free(str);
	free(mem);
	free(cgroupname);
	free(cpus);
	return rc;
}

/*
   If path is empy or ends with  "/." or "/.. return -1 else return 0;
 */
static int bad_path(const char *path) {
	const char *ptr;
	ptr = path;
	while (*ptr) ptr++;
	if (ptr == path) return -1; // ptr null
	ptr--;
	if (ptr != path && *ptr  == '.') {
		ptr--;
		if (*ptr  == '/') return -1; // path ends in /.
		if (*ptr  == '.') {
			if (ptr != path) {
				ptr--;
				if (*ptr  == '/') return -1; // path ends in /..
			}
		}
	}
	return 0;
}

static int rsynccmd(const char * src, const char *dst, char **cmdbuf)
{
	char *buf = NULL;
	char *newbuf = NULL;
	glob_t fglob;
	fglob.gl_offs = 0;
	int flags = GLOB_PERIOD;
	unsigned int i = 0;
	int rc = -1;

	/* match glob for all files in src dir */
	if (asprintf(&buf, "%s/*", src) == -1) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}

	if (glob(buf, flags, NULL, &fglob) != 0) {
		free(buf); buf = NULL;
		return -1;
	}

	free(buf); buf = NULL;

	for ( i=0; i < fglob.gl_pathc; i++) {
		const char *path = fglob.gl_pathv[i];

		if (bad_path(path)) continue;

		if (!buf) {
			if (asprintf(&newbuf, "\'%s\'", path) == -1) {
				fprintf(stderr, "Out of memory\n");
				goto err;
			}
		} else {
			if (asprintf(&newbuf, "%s  \'%s\'", buf, path) == -1) {
				fprintf(stderr, "Out of memory\n");
				goto err;
			}
		}

		free(buf); buf = newbuf;
		newbuf = NULL;
	}

	if (buf) {
		if (asprintf(&newbuf, "/usr/bin/rsync -trlHDq %s '%s'", buf, dst) == -1) {
			fprintf(stderr, "Out of memory\n");
			goto err;
		}
		*cmdbuf=newbuf;
	}
	else {
		*cmdbuf=NULL;
	}
	rc = 0;

err:
	free(buf); buf = NULL;
	globfree(&fglob);
	return rc;
}

/**
 * Clean up runtime temporary directory.  Returns 0 if no problem was detected,
 * >0 if some error was detected, but errors here are treated as non-fatal and
 * left to tmpwatch to finish incomplete cleanup.
 */
static int cleanup_tmpdir(const char *tmpdir, const char *src,
	struct passwd *pwd, int copy_content)
{
	char *cmdbuf = NULL;
	int rc = 0;

	/* rsync files back */
	if (copy_content) {
		if (asprintf(&cmdbuf, "/usr/bin/rsync --exclude=.X11-unix -utrlHDq --delete '%s/' '%s/'", tmpdir, src) == -1) {
			fprintf(stderr, _("Out of memory\n"));
			cmdbuf = NULL;
			rc++;
		}
		if (cmdbuf && spawn_command(cmdbuf, pwd->pw_uid) != 0) {
			fprintf(stderr, _("Failed to copy files from the runtime temporary directory\n"));
			rc++;
		}
		free(cmdbuf); cmdbuf = NULL;
	}

	/* remove files from the runtime temporary directory */
	if (asprintf(&cmdbuf, "/bin/rm -r '%s/' 2>/dev/null", tmpdir) == -1) {
		fprintf(stderr, _("Out of memory\n"));
		cmdbuf = NULL;
		rc++;
	}
	/* this may fail if there's root-owned file left in the runtime tmpdir */
	if (cmdbuf && spawn_command(cmdbuf, pwd->pw_uid) != 0) rc++;
	free(cmdbuf); cmdbuf = NULL;

	/* remove runtime temporary directory */
	setfsuid(0);
	if (rmdir(tmpdir) == -1)
		fprintf(stderr, _("Failed to remove directory %s: %s\n"), tmpdir, strerror(errno));
	setfsuid(pwd->pw_uid);

	return 0;
}

/**
 * seunshare will create a tmpdir in /tmp, with root ownership.  The parent
 * process waits for it child to exit to attempt to remove the directory.  If
 * it fails to remove the directory, we will need to rely on tmpreaper/tmpwatch
 * to clean it up.
 */
static char *create_tmpdir(const char *src, struct stat *src_st,
	struct stat *out_st, struct passwd *pwd, security_context_t execcon)
{
	char *tmpdir = NULL;
	char *cmdbuf = NULL;
	int fd_t = -1, fd_s = -1;
	struct stat tmp_st;
	security_context_t con = NULL;

	/* get selinux context */
	if (execcon) {
		setfsuid(pwd->pw_uid);
		if ((fd_s = open(src, O_RDONLY)) < 0) {
			fprintf(stderr, _("Failed to open directory %s: %s\n"), src, strerror(errno));
			goto err;
		}
		if (fstat(fd_s, &tmp_st) == -1) {
			fprintf(stderr, _("Failed to stat directory %s: %s\n"), src, strerror(errno));
			goto err;
		}
		if (!equal_stats(src_st, &tmp_st)) {
			fprintf(stderr, _("Error: %s was replaced by a different directory\n"), src);
			goto err;
		}
		if (fgetfilecon(fd_s, &con) == -1) {
			fprintf(stderr, _("Failed to get context of the directory %s: %s\n"), src, strerror(errno));
			goto err;
		}

		/* ok to not reach this if there is an error */
		setfsuid(0);
	}

	if (asprintf(&tmpdir, "/tmp/.sandbox-%s-XXXXXX", pwd->pw_name) == -1) {
		fprintf(stderr, _("Out of memory\n"));
		tmpdir = NULL;
		goto err;
	}
	if (mkdtemp(tmpdir) == NULL) {
		fprintf(stderr, _("Failed to create temporary directory: %s\n"), strerror(errno));
		goto err;
	}

	/* temporary directory must be owned by root:user */
	if (verify_directory(tmpdir, NULL, out_st) < 0) {
		goto err;
	}

	if (check_owner_uid(0, tmpdir, out_st) < 0)
		goto err;

	if (check_owner_gid(getgid(), tmpdir, out_st) < 0)
		goto err;

	/* change permissions of the temporary directory */
	if ((fd_t = open(tmpdir, O_RDONLY)) < 0) {
		fprintf(stderr, _("Failed to open directory %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}
	if (fstat(fd_t, &tmp_st) == -1) {
		fprintf(stderr, _("Failed to stat directory %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}
	if (!equal_stats(out_st, &tmp_st)) {
		fprintf(stderr, _("Error: %s was replaced by a different directory\n"), tmpdir);
		goto err;
	}
	if (fchmod(fd_t, 01770) == -1) {
		fprintf(stderr, _("Unable to change mode on %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}
	/* re-stat again to pick change mode */
	if (fstat(fd_t, out_st) == -1) {
		fprintf(stderr, _("Failed to stat directory %s: %s\n"), tmpdir, strerror(errno));
		goto err;
	}

	/* copy selinux context */
	if (execcon) {
		if (fsetfilecon(fd_t, con) == -1) {
			fprintf(stderr, _("Failed to set context of the directory %s: %s\n"), tmpdir, strerror(errno));
			goto err;
		}
	}

	setfsuid(pwd->pw_uid);

	if (rsynccmd(src, tmpdir, &cmdbuf) < 0) {
		goto err;
	}

	/* ok to not reach this if there is an error */
	setfsuid(0);

	if (cmdbuf && spawn_command(cmdbuf, pwd->pw_uid) != 0) {
		fprintf(stderr, _("Failed to populate runtime temporary directory\n"));
		cleanup_tmpdir(tmpdir, src, pwd, 0);
		goto err;
	}

	goto good;
err:
	free(tmpdir); tmpdir = NULL;
good:
	free(cmdbuf); cmdbuf = NULL;
	freecon(con); con = NULL;
	if (fd_t >= 0) close(fd_t);
	if (fd_s >= 0) close(fd_s);
	return tmpdir;
}

int main(int argc, char **argv) {
	int status = -1;
	security_context_t execcon = NULL;

	int clflag;		/* holds codes for command line flags */
	int usecgroups = 0;

	char *homedir_s = NULL;	/* homedir spec'd by user in argv[] */
	char *tmpdir_s = NULL;	/* tmpdir spec'd by user in argv[] */
	char *tmpdir_r = NULL;	/* tmpdir created by seunshare */

	struct stat st_homedir;
	struct stat st_tmpdir_s;
	struct stat st_tmpdir_r;

	const struct option long_options[] = {
		{"homedir", 1, 0, 'h'},
		{"tmpdir", 1, 0, 't'},
		{"verbose", 1, 0, 'v'},
		{"cgroups", 1, 0, 'c'},
		{"context", 1, 0, 'Z'},
		{"capabilities", 1, 0, 'C'},
		{NULL, 0, 0, 0}
	};

	uid_t uid = getuid();
/*
	if (!uid) {
		fprintf(stderr, _("Must not be root"));
		return -1;
	}
*/

	struct passwd *pwd=getpwuid(uid);
	if (!pwd) {
		perror(_("getpwduid failed"));
		return -1;
	}

	if (verify_shell(pwd->pw_shell) < 0) {
		fprintf(stderr, _("Error: User shell is not valid\n"));
		return -1;
	}

	while (1) {
		clflag = getopt_long(argc, argv, "Ccvh:t:Z:", long_options, NULL);
		if (clflag == -1)
			break;

		switch (clflag) {
		case 't':
			tmpdir_s = optarg;
			break;
		case 'h':
			homedir_s = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'c':
			usecgroups = 1;
			break;
		case 'C':
			cap_set = CAPNG_SELECT_CAPS;
			break;
		case 'Z':
			execcon = optarg;
			break;
		default:
			fprintf(stderr, "%s\n", USAGE_STRING);
			return -1;
		}
	}

	if (! homedir_s && ! tmpdir_s) {
		fprintf(stderr, _("Error: tmpdir and/or homedir required\n %s\n"), USAGE_STRING);
		return -1;
	}

	if (argc - optind < 1) {
		fprintf(stderr, _("Error: executable required\n %s\n"), USAGE_STRING);
		return -1;
	}

	if (execcon && is_selinux_enabled() != 1) {
		fprintf(stderr, _("Error: execution context specified, but SELinux is not enabled\n"));
		return -1;
	}

	if (set_signal_handles())
		return -1;

	if (usecgroups && setup_cgroups() < 0)
		return  -1;

	/* set fsuid to ruid */
	/* Changing fsuid is usually required when user-specified directory is
	 * on an NFS mount.  It's also desired to avoid leaking info about
	 * existence of the files not accessible to the user. */
	setfsuid(uid);

	/* verify homedir and tmpdir */
	if (homedir_s && (
		verify_directory(homedir_s, NULL, &st_homedir) < 0 ||
		check_owner_uid(uid, homedir_s, &st_homedir))) return -1;
	if (tmpdir_s && (
		verify_directory(tmpdir_s, NULL, &st_tmpdir_s) < 0 ||
		check_owner_uid(uid, tmpdir_s, &st_tmpdir_s))) return -1;
	setfsuid(0);

	/* create runtime tmpdir */
	if (tmpdir_s && (tmpdir_r = create_tmpdir(tmpdir_s, &st_tmpdir_s,
						  &st_tmpdir_r, pwd, execcon)) == NULL) {
		fprintf(stderr, _("Failed to create runtime temporary directory\n"));
		return -1;
	}

	/* spawn child process */
	int child = fork();
	if (child == -1) {
		perror(_("Unable to fork"));
		goto err;
	}

	if (child == 0) {
		char *display = NULL;
		int rc = -1;

		if (unshare(CLONE_NEWNS) < 0) {
			perror(_("Failed to unshare"));
			goto childerr;
		}

		/* assume fsuid==ruid after this point */
		setfsuid(uid);

		/* mount homedir and tmpdir, in this order */
		if (homedir_s && seunshare_mount(homedir_s, pwd->pw_dir,
			&st_homedir) != 0) goto childerr;
		if (tmpdir_s &&	seunshare_mount(tmpdir_r, "/tmp",
			&st_tmpdir_r) != 0) goto childerr;

		if (drop_privs(uid) != 0) goto childerr;

		/* construct a new environment */
		if ((display = getenv("DISPLAY")) != NULL) {
			if ((display = strdup(display)) == NULL) {
				perror(_("Out of memory"));
				goto childerr;
			}
		}
		if ((rc = clearenv()) != 0) {
			perror(_("Failed to clear environment"));
			goto childerr;
		}
		if (display)
			rc |= setenv("DISPLAY", display, 1);
		rc |= setenv("HOME", pwd->pw_dir, 1);
		rc |= setenv("SHELL", pwd->pw_shell, 1);
		rc |= setenv("USER", pwd->pw_name, 1);
		rc |= setenv("LOGNAME", pwd->pw_name, 1);
		rc |= setenv("PATH", DEFAULT_PATH, 1);
		if (rc != 0) {
			fprintf(stderr, _("Failed to construct environment\n"));
			goto childerr;
		}

		/* selinux context */
		if (execcon && setexeccon(execcon) != 0) {
			fprintf(stderr, _("Could not set exec context to %s.\n"), execcon);
			goto childerr;
		}

		if (chdir(pwd->pw_dir)) {
			perror(_("Failed to change dir to homedir"));
			goto childerr;
		}
		setsid();
		execv(argv[optind], argv + optind);
		fprintf(stderr, _("Failed to execute command %s: %s\n"), argv[optind], strerror(errno));
childerr:
		free(display);
		exit(-1);
	}

	drop_caps();

	/* parent waits for child exit to do the cleanup */
	waitpid(child, &status, 0);
	status_to_retval(status, status);

	if (tmpdir_r) cleanup_tmpdir(tmpdir_r, tmpdir_s, pwd, 1);

err:
	free(tmpdir_r);
	return status;
}
