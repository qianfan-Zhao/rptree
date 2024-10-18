/*
 * Show running process tree based on ptrace.
 *
 * qianfan Zhao <qianfanguijin@163.com>
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <getopt.h>
#include "list_head.h"
#include "rptree.h"
#include "cJSON.h"

static bool option_noenv = false;

struct process {
	pid_t			pid;
	pid_t			ppid;
	char			cwd[1024];
	char			*cmdline;
	size_t			cmdline_len;
	char			*environ;
	size_t			environ_len;

	struct timespec		boottime;

	struct list_head	head;
	struct list_head	childs;
	struct process		*parent;
};

static LIST_HEAD(orphan_lists);
static struct process *root_process = NULL;

static struct process *alloc_process(void)
{
	struct process *p = calloc(1, sizeof(*p));

	if (p) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &p->boottime);
		list_init(&p->head);
		list_init(&p->childs);
	}

	return p;
}

static struct process *process_find_in(struct process *root, pid_t pid)
{
	struct process *p;

	if (root->pid == pid)
		return root;

	list_for_each_entry(p, &root->childs, head, struct process) {
		struct process *matched;

		matched = process_find_in(p, pid);
		if (matched)
			return matched;
	}

	return NULL;
}

static struct process *process_find(pid_t pid)
{
	return process_find_in(root_process, pid);
}

static const char *next_string(const char *buf, size_t bufsz, const char *s)
{
	if (s == NULL)
		return buf;

	for (; s - buf < (int)bufsz; s++) {
		if (*s == '\0') {
			s++;
			if (s - buf < (int)bufsz)
				return s;
		}
	}

	return NULL;
}

#define foreach_string(i, buf, bufsz) \
	for (i = NULL; (i = next_string(buf, bufsz, i)) != NULL; )

static void show_process_level(FILE *fp, int level, const char *marker)
{
	if (level > 0)
		fprintf(fp, "%*s%s", (level - 1) * 4, "", marker);
}

static void show_process_timestamp(FILE *fp, struct process *p)
{
	struct timespec diff = { 0 };

	timespecsub(&p->boottime, &root_process->boottime, &diff);

	fprintf(fp, "%ld.%03ld ", diff.tv_sec, diff.tv_nsec / 1000000);
}

static bool process_has_env(struct process *p, const char *env)
{
	const char *s;

	if (!p || !p->environ)
		return false;

	foreach_string(s, p->environ, p->environ_len) {
		if (!strcmp(s, env))
			return true;
	}

	return false;
}

/* |---- 0.000 [9079] /usr/bin/echo 1.sh
 * |**** -ENV SHLVL=1
 * |**** -ENV _=/home/qianfan/debug/port/github-os/rptree/./a.out
 * |**** +ENV _=/usr/bin/echo
 * |**** +ENV SHLVL=2
 */
static bool ignore_env(const char *s)
{
	static const char *env_ignore_lists[] = {
		"SHLVL=",
		"_=",
		NULL,
	};

	for (size_t i = 0; env_ignore_lists[i]; i++) {
		const char *ignore = env_ignore_lists[i];

		if (!strncmp(ignore, s, strlen(ignore)))
			return true;
	}

	return false;
}

static void show_process_environ(FILE *fp, struct process *p, int level)
{
	struct process *parent = p->parent;
	const char *s;

	/* do not show the root process's env */
	if (level == 0)
		return;

#if 0 /* for debug perpose */
	foreach_string(s, p->environ, p->environ_len) {
		show_process_level(fp, level, "|xxxx ");
		fprintf(fp, "%s\n", s);
	}
#endif

	if (parent && parent->environ) {
		foreach_string(s, parent->environ, parent->environ_len) {
			if (!process_has_env(p, s) && !ignore_env(s)) {
				show_process_level(fp, level, "    \\- ");
				fprintf(fp, "%s\n", s);
			}
		}
	}

	foreach_string(s, p->environ, p->environ_len) {
		if (!process_has_env(parent, s) && !ignore_env(s)) {
			show_process_level(fp, level, "    \\+ ");
			fprintf(fp, "%s\n", s);
		}
	}
}

static void show_process_cwd(FILE *fp, struct process *p, int level)
{
	struct process *parent = p->parent;

	if (level == 0)
		return;

	if (parent && strcmp(p->cwd, parent->cwd)) {
		show_process_level(fp, level, "|...$ ");
		fprintf(fp, "%s\n", p->cwd);
	}
}

static void show_process(FILE *fp, struct process *p, int level)
{
	const char *s;

	show_process_cwd(fp, p, level);

	show_process_level(fp, level, "|.... ");
	show_process_timestamp(fp, p);

	fprintf(fp, "[%d]", p->pid);
	foreach_string(s, p->cmdline, p->cmdline_len) {
		if (strchr(s, ' '))
			fprintf(fp, " '%s'", s);
		else
			fprintf(fp, " %s", s);

	}
	fprintf(fp, "\n");

	if (!option_noenv)
		show_process_environ(fp, p, level);
}

static void show_process_tree(FILE *fp, struct process *root, int level)
{
	struct process *p;

	show_process(fp, root, level);

	list_for_each_entry(p, &root->childs, head, struct process)
		show_process_tree(fp, p, level + 1);
}

static void show_rptree(void)
{
	return show_process_tree(stdout, root_process, 0);
}

static cJSON *process_to_json_object(struct process *root)
{
	cJSON *json = cJSON_CreateObject();
	cJSON *cmd, *env;
	const char *s;

	if (!json)
		return json;

	cJSON_AddNumberToObject(json, "pid", root->pid);
	cJSON_AddNumberToObject(json, "ppid", root->ppid);
	cJSON_AddNumberToObject(json, "boot.sec", root->boottime.tv_sec);
	cJSON_AddNumberToObject(json, "boot.nsec", root->boottime.tv_nsec);
	cJSON_AddStringToObject(json, "cwd", root->cwd);

	cmd = cJSON_AddArrayToObject(json, "cmdline");
	foreach_string(s, root->cmdline, root->cmdline_len)
		cJSON_AddItemToArray(cmd, cJSON_CreateString(s));

	env = cJSON_AddArrayToObject(json, "environ");
	foreach_string(s, root->environ, root->environ_len)
		cJSON_AddItemToArray(env, cJSON_CreateString(s));

	return json;
}

static int process_tree_addto_json(cJSON *json_arrays, struct process *root)
{
	cJSON *json;

	json = process_to_json_object(root);
	if (!list_empty(&root->childs)) {
		cJSON *childs = cJSON_AddArrayToObject(json, "childs");
		struct process *p;

		list_for_each_entry(p, &root->childs, head, struct process)
			process_tree_addto_json(childs, p);
	}

	cJSON_AddItemToArray(json_arrays, json);
	return 0;
}

static void orphan_find_parent(void)
{
	struct process *orphan, *next, *parent;
	int active = 0;

	do {
		active = 0;

		list_for_each_entry_safe(orphan, next, &orphan_lists,
					head, struct process) {
			parent = process_find(orphan->ppid);
			if (parent) {
				/* it's parent ready, move it */
				list_del(&orphan->head);

				active = 1;
				orphan->parent = parent;
				list_init(&orphan->head);
				list_add_tail(&orphan->head, &parent->childs);
				break;
			}
		}
	} while (active);
}

static void warning_orphan(void)
{
	struct process *orphan;

	list_for_each_entry(orphan, &orphan_lists, head, struct process) {
		fprintf(stderr, "Warnning: orphan %d started by %d, %s\n",
			orphan->pid, orphan->ppid, orphan->cmdline);
	}
}

static void add_process(pid_t pid)
{
	struct process *parent, *self;
	pid_t ppid;

	ppid = procfs_get_ppid(pid);
	if (ppid < 0)
		return;

	/* we got the ptrace message maybe not in order mode such as this
	 * script: `self_path=$(dirname "$(readlink -f "$0")")`
	 * we got readlink first and it's parent dirname later.
	 *
	 * ppid 10758 -> pid 10759, sh
	 * ppid 10760 -> pid 10761, readlink
	 * ppid 10759 -> pid 10760, dirname
	 */
	for (int try = 0; try < 2; try++) {
		parent = process_find(ppid);
		if (parent)
			break;

		switch (try) {
		case 0:
			add_process(ppid);
			break;
		}
	}

	self = alloc_process();
	self->pid = pid;
	self->ppid = ppid;
	self->parent = parent; /* parent maybe NULL */
	self->cmdline = procfs_alloc(pid, "cmdline", &self->cmdline_len);
	self->environ = procfs_alloc(pid, "environ", &self->environ_len);
	procfs_get_cwd(pid, self->cwd, sizeof(self->cwd));

	if (parent) {
		list_add_tail(&self->head, &parent->childs);
		orphan_find_parent();
	} else {
		list_add_tail(&self->head, &orphan_lists);
	}
}

static cJSON *rptree_to_json(void)
{
	cJSON *arrays = cJSON_CreateArray();

	if (!arrays)
		return arrays;

	process_tree_addto_json(arrays, root_process);
	return arrays;
}

static int rptree_write_to_json(const char *name)
{
	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0664);
	char *s = NULL;
	cJSON *json;

	if (fd < 0) {
		fprintf(stderr, "Error: create %s failed\n", name);
		return fd;
	}

	json = rptree_to_json();
	if (!json) {
		fprintf(stderr, "Error: convert rptree to json failed\n");
		close(fd);
		return -1;
	}

	s = cJSON_Print(json);
	write(fd, s, strlen(s));
	close(fd);

	cJSON_free(s);
	cJSON_Delete(json);

	return 0;
}

enum {
	ARG_NOENV = 1,
	ARG_VERSION,

	ARG_HELP = 'h',
	ARG_WRITE = 'w',
};

static struct option long_options[] = {
	/* name		has_arg,		*flag,	val */
	{ "write",	required_argument,	NULL,	ARG_WRITE	},
	{ "noenv",	no_argument,		NULL,	ARG_NOENV 	},
	{ "version",	no_argument,		NULL,	ARG_VERSION	},
	{ "help",	no_argument,		NULL,	ARG_HELP 	},
	{ NULL,		0,			NULL,	0   		},
};

static void print_usage(void)
{
	fprintf(stderr, "rptree: show running process tree\n");
	fprintf(stderr, "Usage: [OPTIONS] -- child [CHILD_ARGS]\n");
	fprintf(stderr, "     --noenv:             do not show environ\n");
	fprintf(stderr, "     --version:           show version\n");
	fprintf(stderr, "  -h --help:              show this help message\n");
}

int main(int argc, char **argv)
{
	const char *write_json_name = NULL;
	int main_argc, child_argc = argc;
	int wstatus = 0;
	pid_t pid;

	/* args after '--' will passed to the subcommand */
	for (main_argc = 0; main_argc < argc; main_argc++, child_argc--) {
		if (!strcmp(argv[main_argc], "--")) {
			child_argc--; /* skip '--' */
			argv[main_argc] = NULL;
			break;
		}
	}

	while (1) {
		int option_index = 0;
		int c;

		c = getopt_long(main_argc, argv, "hw:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h': /* help */
			print_usage();
			return 0;
		case ARG_WRITE:
			write_json_name = optarg;
			break;
		case ARG_VERSION:
			printf("%s\n", RPTREE_VERSION);
			return 0;
		case ARG_NOENV:
			option_noenv = true;
			break;
		}
	}

	if (child_argc == 0) {
		fprintf(stderr, "Error: missing child args\n");
		return -1;
	}

	root_process = alloc_process();
	if (!root_process)
		return -1;

	root_process->pid = getpid();
	root_process->cmdline =
		procfs_alloc(root_process->pid, "cmdline", &root_process->cmdline_len);
	root_process->environ =
		procfs_alloc(root_process->pid, "environ", &root_process->environ_len);
	procfs_get_cwd(root_process->pid, root_process->cwd, sizeof(root_process->cwd));

	pid = fork();
	switch (pid) {
	case -1:
		fprintf(stderr, "Error: fork failed.\n");
		return pid;
	case 0:
		/* child */
		ptrace(PTRACE_TRACEME);
		raise(SIGSTOP);
		return execvp(argv[main_argc + 1], &argv[main_argc + 1]);
	}

	/* waiting child ready */
	wait(&wstatus);

	/* PTRACE_O_TRACEFORK:
	 * Stop the tracee at the next fork(2) and
         * automatically start tracing the newly forked process
	 */
	ptrace(PTRACE_SETOPTIONS, pid, NULL,
		PTRACE_O_TRACEEXEC |
		PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE);
	ptrace(PTRACE_CONT, pid, NULL, 0 /* signal */);

	while((pid = wait(&wstatus)) > 0) {
		if(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
			switch (wstatus >> 8) {
			case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
				add_process(pid);
				break;
			}
		}

		ptrace(PTRACE_CONT, pid, NULL, 0 /* signal */);
	}

	printf("\n");
	printf("Running process tree generated by rptree %s\n", RPTREE_VERSION);
	orphan_find_parent();
	show_rptree();
	warning_orphan();

	if (write_json_name)
		rptree_write_to_json(write_json_name);

	return WEXITSTATUS(wstatus);
}
