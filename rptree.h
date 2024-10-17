/*
 * running process tree
 *
 * qianfan Zhao <qianfanguijin@163.com>
 */
#ifndef RPTREE_H
#define RPTREE_H

#include <stdio.h>
#include <unistd.h>

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
int procfs_read(pid_t pid, const char *name, char *buf, size_t bufsz);
void *procfs_alloc(pid_t pid, const char *name, size_t *ret_filesize);

#endif
