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
	void *buf = NULL;

	if (fd < 0)
		return buf;

	buf = file_alloc(fd, ret_filesize);
	close(fd);

	return buf;
}

void *file_alloc(int fd, size_t *ret_filesize)
{
	size_t filesz = 0, bufsz = 128;
	uint8_t *buf = NULL;

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

int procfs_get_fdname(pid_t pid, int fd, char *buf, size_t bufsz)
{
	char path[1024];
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	ret = readlink(path, buf, bufsz - 1);
	if (ret < 0)
		return ret;

	buf[ret] = '\0';
	return 0;
}

/*
 * |.... 0.002 [465] /usr/bin/echo 'hello world'
 *    |...0 /dev/pts/3
 *    |...1 pipe:[2343]
 *    |.... 0.002 [466] tr ' ' :
 *    |...0 pipe:[2343]
 *    |...1 pipe:[2344]
 *    |.... 0.002 [467] awk -F: '{print $2}'
 *    |...0 pipe:[2344]
 *    |...1 /dev/pts/3
 */
int procfs_get_pipefd(pid_t pid, int fd)
{
	char *endp, filename[1024];
	long pipe;
	int ret;

	ret = procfs_get_fdname(pid, fd, filename, sizeof(filename));
	if (ret < 0)
		return fd;

	if (strncmp(filename, "pipe:[", 6)) /* not a pipe */
		return -1;

	pipe = strtol(filename + 6, &endp, 10);
	if (*endp != ']') /* bad pipe number */
		return -1;

	return (int)pipe;
}
