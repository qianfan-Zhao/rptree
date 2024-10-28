/*
 * running process tree
 *
 * qianfan Zhao <qianfanguijin@163.com>
 */
#ifndef RPTREE_H
#define RPTREE_H

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include "list_head.h"

struct process {
	pid_t			pid;
	pid_t			ppid;
	char			cwd[1024];
	char			*cmdline;
	size_t			cmdline_len;
	char			*environ;
	size_t			environ_len;
	int			pipe_fd0;
	int			pipe_fd1;

	struct timespec		boottime;

	struct list_head	head;
	struct list_head	childs;
	struct process		*parent;

	struct process		*pipe_next;
};

struct process *get_root_process(void);
struct process *process_find(pid_t pid);
bool process_has_env(struct process *, const char *);
const char *next_string(const char *buf, size_t bufsz, const char *s);
#define foreach_string(i, buf, bufsz) \
	for (i = NULL; (i = next_string(buf, bufsz, i)) != NULL; )
size_t count_string(const char *buf, size_t bufsz);
int rpshell(char *rpshell_command);

struct show_rptree_option {
	bool			show_env;
	bool			show_pipefd;
	bool			show_cwd;
	bool			show_ts;
};

void show_rptree(struct show_rptree_option *opt);

#define timespecadd(tsp, usp, vsp)					\
do {									\
	(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;			\
	(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;		\
	if ((vsp)->tv_nsec >= 1000000000L) {				\
		(vsp)->tv_sec++;					\
		(vsp)->tv_nsec -= 1000000000L;				\
	}								\
} while (/* CONSTCOND */ 0)

#define timespecsub(tsp, usp, vsp)					\
do {									\
	(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;			\
	(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;		\
	if ((vsp)->tv_nsec < 0) {					\
		(vsp)->tv_sec--;					\
		(vsp)->tv_nsec += 1000000000L;				\
	}								\
} while (/* CONSTCOND */ 0)

pid_t procfs_get_ppid(pid_t pid);
void *file_alloc(int fd, size_t *ret_filesize);
int procfs_read(pid_t pid, const char *name, char *buf, size_t bufsz);
void *procfs_alloc(pid_t pid, const char *name, size_t *ret_filesize);
int procfs_get_cwd(pid_t pid, char *buf, size_t bufsz);
int procfs_get_fdname(pid_t pid, int fd, char *buf, size_t bufsz);
int procfs_get_pipefd(pid_t pid, int fd);

#endif
