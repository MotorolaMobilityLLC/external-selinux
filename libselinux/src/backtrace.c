#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <stdio.h>
#include <limits.h>

int security_get_backtrace_switch(void)
{
	int fd, ret, backtrace_enable = 0;
	char path[PATH_MAX];
	char buf[20];

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/backtrace_enable", selinux_mnt);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	memset(buf, 0, sizeof buf);
	ret = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (ret < 0)
		return -1;

	if (sscanf(buf, "%d", &backtrace_enable) != 1)
		return -1;

	return !!backtrace_enable;
}

hidden_def(security_get_backtrace_switch)

int security_get_backtrace_filter(char *avc_backtrace_filter)
{
	int fd, ret;
	char path[PATH_MAX];
	char buf[32], *backtrace_filter = NULL;

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/backtrace_filter", selinux_mnt);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	memset(buf, 0, sizeof buf);
	ret = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (ret < 0)
		return -1;

	backtrace_filter = malloc(sizeof(char *));
	if (sscanf(buf, "%s", backtrace_filter) != ret)
		return -1;
	avc_backtrace_filter = backtrace_filter;

	return 0;
}

hidden_def(security_get_backtrace_filter)

