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

static LIST_HEAD(orphan_lists);
static struct process *root_process = NULL;

struct process *get_root_process(void)
{
	return root_process;
}

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

struct process *process_find(pid_t pid)
{
	return process_find_in(root_process, pid);
}

const char *next_string(const char *buf, size_t bufsz, const char *s)
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

size_t count_string(const char *buf, size_t bufsz)
{
	const char *s;
	size_t n = 0;

	foreach_string(s, buf, bufsz)
		++n;

	return n;
}

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

bool process_has_env(struct process *p, const char *env)
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

static void show_process(FILE *fp, struct process *p, int level,
			 struct show_rptree_option *opt)
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

	if (!opt->noenv)
		show_process_environ(fp, p, level);
}

static void show_process_tree(FILE *fp, struct process *root, int level,
			      struct show_rptree_option *opt)
{
	struct process *p;

	show_process(fp, root, level, opt);

	list_for_each_entry(p, &root->childs, head, struct process)
		show_process_tree(fp, p, level + 1, opt);
}

void show_rptree(struct show_rptree_option *opt)
{
	return show_process_tree(stdout, root_process, 0, opt);
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

static double cJSON_GetNumberValueIn(cJSON *root, const char *name)
{
	cJSON *obj = cJSON_GetObjectItem(root, name);

	return cJSON_GetNumberValue(obj);
}

static const char *cJSON_GetStringValueIn(cJSON *root, const char *name)
{
	cJSON *obj = cJSON_GetObjectItem(root, name);

	return cJSON_GetStringValue(obj);
}

static size_t cJSON_StringArrayTotalLength(cJSON *arrays)
{
	size_t total = 0;
	cJSON *json;

	cJSON_ArrayForEach(json, arrays)
		total += strlen(cJSON_GetStringValue(json)) + 1; /* include null */

	return total;
}

static char *cJSON_StringArrayPrint(cJSON *arrays, size_t *total_length)
{
	size_t i = 0, len = cJSON_StringArrayTotalLength(arrays);
	char *s = calloc(1, len);
	cJSON *json;

	if (!s)
		return s;

	cJSON_ArrayForEach(json, arrays) {
		const char *v = cJSON_GetStringValue(json);
		size_t l = strlen(v) + 1; /* including null */

		memcpy(s + i, v, l);
		i += l;
	}

	*total_length = len;
	return s;
}

static struct process *process_from_json(cJSON *json, struct process *parent)
{
	struct process *p = alloc_process();

	if (!p)
		return p;

	p->pid = (pid_t)cJSON_GetNumberValueIn(json, "pid");
	p->ppid = (pid_t)cJSON_GetNumberValueIn(json, "ppid");
	p->boottime.tv_sec = (time_t)cJSON_GetNumberValueIn(json, "boot.sec");
	p->boottime.tv_nsec = (long)cJSON_GetNumberValueIn(json, "boot.nsec");
	snprintf(p->cwd, sizeof(p->cwd), "%s", cJSON_GetStringValueIn(json, "cwd"));

	p->cmdline = cJSON_StringArrayPrint(
			cJSON_GetObjectItem(json, "cmdline"), &p->cmdline_len);
	p->environ = cJSON_StringArrayPrint(
			cJSON_GetObjectItem(json, "environ"), &p->environ_len);

	if (parent) {
		p->parent = parent;
		list_add_tail(&p->head, &parent->childs);
	}

	return p;
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

static int rptree_load_from_json(cJSON *root, struct process *parent)
{
	int ret = 0;
	cJSON *json;

	cJSON_ArrayForEach(json, root) {
		struct process *p = process_from_json(json, parent);
		cJSON *childs;

		if (!p)
			return -1;

		/* the first process will be root_process */
		if (!root_process)
			root_process = p;

		childs = cJSON_GetObjectItem(json, "childs");
		if (childs) {
			ret = rptree_load_from_json(childs, p);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int rptree_load_from(const char *name)
{
	int ret, fd = open(name, O_RDONLY);
	cJSON *json;
	size_t size;
	char *s;

	if (fd < 0) {
		fprintf(stderr, "Error: open %s failed\n", name);
		return fd;
	}

	s = file_alloc(fd, &size);
	close(fd);

	if (!s) {
		fprintf(stderr, "Error: alloc read %s failed\n", name);
		return -1;
	}

	json = cJSON_ParseWithLength(s, size);
	free(s);
	if (!json) {
		fprintf(stderr, "Error: parse json failed\n");
		return -1;
	}

	ret = rptree_load_from_json(json, root_process);
	cJSON_Delete(json);

	return ret;
}

enum {
	ARG_NOENV = 1,
	ARG_VERSION,

	ARG_CMD = 'c',
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
	fprintf(stderr, "  -w --write file:        write process's information to file\n");
	fprintf(stderr, "  -c command:             run builtin command\n");
	fprintf(stderr, "  -h --help:              show this help message\n");
}

static int propagate_signal(int wstatus)
{
	int sig = 0;

	if (WIFSTOPPED(wstatus)) {
		#define case_stopsig(_sig) case _sig: sig = _sig; break

		switch (WSTOPSIG(wstatus)) {
		case_stopsig(SIGTERM);
		case_stopsig(SIGINT);
		case_stopsig(SIGQUIT);
		case_stopsig(SIGHUP);
		case_stopsig(SIGPIPE);
		case_stopsig(SIGCHLD);
		default:
			if (WSTOPSIG(wstatus) != SIGTRAP)
				sig = WSTOPSIG(wstatus);
			break;
		}

		#undef case_stopsig
	}

	return sig;
}

int main(int argc, char **argv)
{
	struct show_rptree_option opt = { .noenv = false };
	const char *write_json_name = NULL;
	int main_argc, child_argc = argc;
	char *rpshell_command = NULL;
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

		c = getopt_long(main_argc, argv, "hc:w:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h': /* help */
			print_usage();
			return 0;
		case ARG_CMD:
			rpshell_command = optarg;
			break;
		case ARG_WRITE:
			write_json_name = optarg;
			break;
		case ARG_VERSION:
			printf("%s\n", RPTREE_VERSION);
			return 0;
		case ARG_NOENV:
			opt.noenv = true;
			break;
		}
	}

	if (optind < main_argc) {
		const char *filename = argv[optind];
		int ret;

		ret = rptree_load_from(filename);
		if (ret < 0)
			return ret;

		return rpshell(rpshell_command);
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
		PTRACE_O_EXITKILL |
		PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE);
	ptrace(PTRACE_CONT, pid, NULL, 0 /* signal */);

	while((pid = wait(&wstatus)) > 0) {
		int sig = propagate_signal(wstatus);

		if(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
			switch (wstatus >> 8) {
			case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
				sig = 0;
				add_process(pid);
				break;
			case SIGTRAP | (PTRACE_EVENT_FORK << 8):
			case SIGTRAP | (PTRACE_EVENT_CLONE << 8):
				sig = 0;
				break;
			default:
				sig = SIGTRAP;
				break;
			}
		}

		ptrace(PTRACE_CONT, pid, NULL, sig /* signal */);
	}

	orphan_find_parent();
	warning_orphan();

	if (write_json_name) {
		rptree_write_to_json(write_json_name);
	} else {
		printf("\n");
		printf("Running process tree generated by rptree %s\n", RPTREE_VERSION);
		show_rptree(&opt);
	}

	return WEXITSTATUS(wstatus);
}
