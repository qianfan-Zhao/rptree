/*
 * procfs helper interface
 *
 * qianfan Zhao <qianfanguijin@163.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "rptree.h"

static int procfs_open(pid_t pid, const char *name)
{
	char path[1024];

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);

	return open(path, O_RDONLY);
}

static int procfs_read_fd(int fd, char *buf, size_t bufsz)
{
	int ret;

	ret = read(fd, buf, bufsz - 1);
	if (ret <= 0) {
		buf[0] = '\0';
		return ret;
	}

	if (buf[ret - 1] == '\n')
		ret--;
	buf[ret] = '\0';

	return ret;
}

int procfs_read(pid_t pid, const char *name, char *buf, size_t bufsz)
{
	int fd = procfs_open(pid, name);
	int n;

	if (fd < 0)
		return fd;

	n = procfs_read_fd(fd, buf, bufsz);
	close(fd);

	return n;
}

pid_t procfs_get_ppid(pid_t pid)
{
	char statbuf[128], *space = statbuf;
	int ret;

	ret = procfs_read(pid, "stat", statbuf, sizeof(statbuf));
	if (ret < 0)
		return ret;

	/* 6123 (zsh) S 6122 */
	for (int space_count = 0; space_count < 3; space_count++) {
		space = strchr(space, ' ');
		if (!space)
			return -1;
		space++;
	}

	return (pid_t)strtol(space, NULL, 10);
}

void *procfs_alloc(pid_t pid, const char *name, size_t *ret_filesize)
{
	int fd = procfs_open(pid, name);
	size_t filesz = 0, bufsz = 128;
	uint8_t *buf = NULL;

	if (fd < 0)
		return buf;

	while (1) {
		size_t freesz = bufsz - filesz - 1; /* reserved for space */
		void *newptr;
		int ret;

		newptr = realloc(buf, bufsz);
		if (!newptr)
			break;

		buf = newptr;
		ret = read(fd, buf + filesz, freesz);
		if (ret <= 0)
			break;

		filesz += ret;
		buf[filesz] = '\0';
		bufsz *= 2;

		if ((size_t)ret < freesz)
			break;
	}

	*ret_filesize = filesz;
	close(fd);

	return buf;
}

int procfs_get_cwd(pid_t pid, char *buf, size_t bufsz)
{
	char path[1024];
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
	ret = readlink(path, buf, bufsz - 1);
	if (ret < 0)
		return ret;

	buf[ret] = '\0';
	return 0;
}
