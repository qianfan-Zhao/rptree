/*
 * shell interface for rptree
 *
 * qianfan Zhao <qianfanguijin@163.com>
 */

#define _GNU_SOURCE /* for import execvpe */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "rptree.h"
#include "libxopt.h"

struct command {
	const char	*name;
	int		min_argc;
	int		max_argc;
	int		(*handle)(int argc, char **argv);
	const char	*helper;
};

static const struct xopt_option cmd_rptree_options[] = {
	{
		.long_name	= "env",
		.type		= XOPT_TYPE_BOOL,
		.offset		= offsetof(struct show_rptree_option, show_env),
	}, {
		.long_name	= "pipefd",
		.type		= XOPT_TYPE_BOOL,
		.offset		= offsetof(struct show_rptree_option, show_pipefd),
	}, {
		.long_name	= "cwd",
		.type		= XOPT_TYPE_BOOL,
		.offset		= offsetof(struct show_rptree_option, show_cwd),
	}, {
		.long_name	= "ts",
		.type		= XOPT_TYPE_BOOL,
		.offset		= offsetof(struct show_rptree_option, show_ts),
	},
	LIBXOPT_NULLOPTION,
};

static int cmd_print(int argc, char **argv)
{
	struct show_rptree_option opt = { .show_env = false };
	struct xopt *xopt = libxopt_new(cmd_rptree_options, 0);
	int ret;

	ret = libxopt_parse(xopt, argc, argv, &opt);
	libxopt_free(xopt);
	if (ret < 0)
		return ret;

	show_rptree(&opt);
	return 0;
}

static long argv_to_pid(const char *arg)
{
	long pid = -1;
	char *endp;

	if (arg == NULL)
		return pid;

	pid = strtol(arg, &endp, 10);
	if (*endp != '\0') {
		fprintf(stderr, "%s is not a pid number\n", arg);
		return -1;
	}

	return pid;
}

static long argv_get_pid(const char *arg)
{
	static long last_pid = 0;
	long pid;

	if (arg == NULL) {
		if (last_pid == 0) {
			fprintf(stderr, "pid is not selected\n");
			return -1;
		}
		return last_pid;
	}

	pid = argv_to_pid(arg);
	if (pid < 0)
		return pid;

	last_pid = pid;
	return pid;
}

static struct process *argv_get_process(const char *arg)
{
	long pid = argv_get_pid(arg);
	struct process *p;

	if (pid < 0)
		return NULL;

	p = process_find((pid_t)pid);
	if (!p)
		fprintf(stderr, "process with pid %ld is not found\n", pid);

	return p;
}

static int cmd_p(int argc, char **argv)
{
	struct process *p = argv_get_process(argv[1]);
	const char *s;

	if (!p)
		return -1;

	foreach_string(s, p->cmdline, p->cmdline_len) {
		if (strchr(s, ' '))
			printf("\'%s\' ", s);
		else
			printf("%s ", s);
	}
	printf("\n");
	printf("CWD=%s\n", p->cwd);
	foreach_string(s, p->environ, p->environ_len)
		printf("%s\n", s);

	return 0;
}

static void print_process(struct process *p)
{
	size_t len = 0;
	const char *s;

	printf("%-8d", p->pid);
	foreach_string(s, p->cmdline, p->cmdline_len) {
		if (len >= 120 - 4) {
			printf(" ...");
			break;
		}

		len += strlen(s) + 1; /* include space */
		if (strchr(s, ' ')) {
			printf(" \'%s\'", s);
			len += strlen("\'\'");
		} else {
			printf(" %s", s);
		}
	}

	putchar('\n');
}

static int cmd_bt(int argc, char **argv)
{
	struct process *p = argv_get_process(argv[1]);

	if (!p)
		return -1;

	while (p) {
		print_process(p);
		p = p->parent;
	}

	return 0;
}

static bool process_has_name(struct process *p, const char *name)
{
	const char *cmdline = p->cmdline;
	const char *basename;

	basename = strrchr(cmdline, '/');
	if (basename)
		basename = basename + 1;
	else
		basename = cmdline;

	return !strcmp(name, basename);
}

static int process_pgrep_in(struct process *root, const char *name)
{
	int found = 0;
	struct process *p;

	if (process_has_name(root, name)) {
		print_process(root);
		++found;
	}

	list_for_each_entry(p, &root->childs, head, struct process)
		found += process_pgrep_in(p, name);

	return found;
}

static int cmd_diffenv(int argc, char **argv)
{
	struct process *p1, *p2;
	int diff = 0;
	const char *s;

	p1 = process_find(argv_to_pid(argv[1]));
	if (!p1)
		return -1;

	p2 = process_find(argv_to_pid(argv[2]));
	if (!p2)
		return -1;

	foreach_string(s, p2->environ, p2->environ_len) {
		if (!process_has_env(p1, s)) {
			printf("- %s\n", s);
			++diff;
		}
	}

	foreach_string(s, p1->environ, p1->environ_len) {
		if (!process_has_env(p2, s)) {
			printf("+ %s\n", s);
			++diff;
		}
	}

	return -diff;
}

static int cmd_pgrep(int argc, char **argv)
{
	if (process_pgrep_in(get_root_process(), argv[1]) > 0)
		return 0;

	return -1;
}

static void *memdup(const void *buf, size_t bufsz)
{
	void *new = malloc(bufsz);

	if (new)
		memcpy(new, buf, bufsz);

	return new;
}

static int mkdir_p(const char *path, mode_t mode)
{
	int rc;
	char *dir = strdup(path);

	if (!dir) {
		rc = errno;
		fprintf(stderr, "strdup(%s) failed\n", path);
		return -rc;
	}

	/* Starting from the root, work our way out to the end. */
	char *p = strchr(dir + 1, '/');
	while (p) {
		*p = '\0';
		if (mkdir(dir, mode) && errno != EEXIST) {
			rc = errno;
			fprintf(stderr, "mkdir(%s, 0%o) failed\n", dir, mode);
			free(dir);
			return -rc;
		}
		*p = '/';
		p = strchr(p + 1, '/');
	}

	/*
	 * Create the last directory.  We still check EEXIST here in case
	 * of trailing slashes.
	 */
	free(dir);
	if (mkdir(path, mode) && errno != EEXIST) {
		rc = errno;
		fprintf(stderr, "mkdir(%s, 0%o) failed\n", path, mode);
		return -rc;
	}
	return 0;
}

static char **argv_rebuild(char *buf, size_t bufsz, int *ret_argc)
{
	size_t i = 0, count = count_string(buf, bufsz);
	const char *s;
	char **argv;

	/* the last one should be NULL */
	argv = calloc(count + 1, sizeof(char *));
	if (!argv)
		return argv;

	foreach_string(s, buf, bufsz) {
		if (i < count) {
			argv[i] = (char *)s;
			i++;
		}
	}

	if (ret_argc)
		*ret_argc = (int)count;

	return argv;
}

static int cmd_exec(int argc, char **argv)
{
	struct process *p = argv_get_process(argv[1]);
	int wstatus;
	pid_t pid;

	if (!p)
		return -1;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed\n");
		return -1;
	}

	if (pid == 0) { /* child */
		char **argv, **env;
		char *s_cmd, *s_env;

		s_cmd = memdup(p->cmdline, p->cmdline_len);
		if (!s_cmd) {
			fprintf(stderr, "alloc cmdline failed\n");
			exit(EXIT_FAILURE);
		}

		s_env = memdup(p->environ, p->environ_len);
		if (!s_env) {
			fprintf(stderr, "alloc env failed\n");
			exit(EXIT_FAILURE);
		}

		argv = argv_rebuild(s_cmd, p->cmdline_len, NULL);
		if (!argv) {
			fprintf(stderr, "rebuild argv failed\n");
			exit(EXIT_FAILURE);
		}

		env = argv_rebuild(s_env, p->environ_len, NULL);
		if (!env) {
			fprintf(stderr, "rebuild env failed\n");
			exit(EXIT_FAILURE);
		}

		if (mkdir_p(p->cwd, 0755) < 0) {
			fprintf(stderr, "prepare cwd failed\n");
			exit(EXIT_FAILURE);
		}

		chdir(p->cwd);
		execvpe(p->cmdline, argv, env);
		exit(EXIT_FAILURE);
	}

	waitpid(pid, &wstatus, 0);
	return wstatus;
}

#define define_cmd(_name, _min, _max, _func, _helper)	{		\
	.name = _name,							\
	.min_argc = _min,						\
	.max_argc = _max,						\
	.handle = _func,						\
	.helper = _helper,						\
}

static const struct command rpshell_commands[] = {
	define_cmd("print",	1, 2, cmd_print,
		   "print [--noenv]:         show running process tree"),
	define_cmd("p",		1, 2, cmd_p,
		   "p [pid]:                  show process information"),
	define_cmd("diffenv",	3, 3, cmd_diffenv,
		   "diffenv pid1 pid2:        compare two process's env"),
	define_cmd("bt",	1, 2, cmd_bt,
		   "bt [pid]:                 show process's stack"),
	define_cmd("pgrep",	2, 2, cmd_pgrep,
		   "pgrep name:               loopup process"),
	define_cmd("exec",	1, 2, cmd_exec,
		   "exec [pid]:               play process again"),
	define_cmd(NULL, 0, 0, NULL, NULL),
};

static int rpshell_do(int argc, char **argv)
{
	const struct command *cmd = NULL;

	for (size_t i = 0; rpshell_commands[i].name; i++) {
		if (!strcmp(rpshell_commands[i].name, argv[0])) {
			cmd = &rpshell_commands[i];
			break;
		}
	}

	if (!cmd) {
		printf("%s is not found\n", argv[0]);
		return -1;
	}

	if ((cmd->min_argc > 0 && argc < cmd->min_argc)
		|| (cmd->max_argc > 0 && argc > cmd->max_argc)) {
		if (cmd->helper)
			printf("%s\n", cmd->helper);
		return -1;
	}

	return cmd->handle(argc, argv);
}

static int argv_buffer_split(char *buf, char **argv, int max_argv)
{
	int single_quota = 0, double_quota = 0, start = 0;
	int argc = 0;

	for (char *s = buf; *s != '\0'; s++) {
		switch (*s) {
		case '\'':
			if (!double_quota) {
				*s = '\0';
				if (single_quota)
					start = 0;
				single_quota ^= 1;
			}
			break;
		case '\"':
			if (!single_quota) {
				*s = '\0';
				if (double_quota)
					start = 0;
				double_quota ^= 1;
			}
			break;
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			if (!single_quota && !double_quota) {
				start = 0;
				*s = '\0';
			}
			break;
		default:
			if (start == 0) {
				/* the last one should be NULL */
				if (argc < max_argv - 1)
					argv[argc++] = s;
				start = 1;
			}
			break;
		}
	}

	argv[argc] = NULL;
	return argc;
}

static int _rpshell(char *s, int *exit)
{
	#define MAX_ARGV 64
	char *argv[MAX_ARGV];
	int argc;

	argc = argv_buffer_split(s, argv, MAX_ARGV);
	if (argc == 0)
		return 0;

	if (!strcmp(argv[0], "exit")
		|| !strcmp(argv[0], "quit") || !strcmp(argv[0], "q")) {
		*exit = 1;
		return 0;
	}

	return rpshell_do(argc, argv);
}

int rpshell(char *rpshell_command)
{
	int exit = 0, last_ret = 0;

	if (rpshell_command)
		return _rpshell(rpshell_command, &exit);

	while (exit == 0) {
		char linebuf[1024];

		printf("%c ", last_ret == 0 ? '$' : '#');
		fflush(stdout);

		if (!fgets(linebuf, sizeof(linebuf) - 1, stdin)) /* ctrl + d */
			break;

		last_ret = _rpshell(linebuf, &exit);
	}

	return 0;
}
