/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * TODO Balaban Robert-Arian, 334CC
 *
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>


#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1


static bool shell_cd(word_t *dir)
{
	return dir != NULL ? chdir(dir->string) : chdir(getenv("PATH"));
}

static int shell_exit(void)
{
	return SHELL_EXIT;
}

static void cdCmd(const char *s)
{
	int file_descript;

	file_descript = open(s, O_CREAT | O_RDONLY, 0644);
	DIE(file_descript < 0, "open");
	close(file_descript);
}

static int envCmd(const char *k, const char *v)
{
	return setenv(k, v, 1);
}

static int equ(const char *s, const char *d)
{
	return strcmp(s, d) == 0;
}

static void closeDescriptors(int *d)
{
	close(d[0]);
	close(d[1]);
}

static int getFlag(int io_flags, int cmp_flag)
{
	return io_flags == cmp_flag ? O_APPEND : O_TRUNC;
}

static void fail()
{
	exit(EXIT_FAILURE);
}

static void handler(char *cmd)
{
	fprintf(stderr, "Execution failed for '%s'\n", cmd);
	free(cmd);
	fail();
}

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	pid_t np, wp;
	char *cmd, *in, *out, *err, **argv;
	int fd, rc, args, stat, FLAG;

	in = get_word(s->in);
	out = get_word(s->out);
	err = get_word(s->err);
	argv = get_argv(s, &args);
	cmd = get_word(s->verb);

	if (equ(cmd, "exit") || equ(cmd, "quit")) {
		free(cmd);
		return shell_exit();
	}
	if (equ(cmd, "cd")) {
		if (s->out != NULL && s->out->string != NULL)
			cdCmd(s->out->string);
		if (s->err != NULL && s->err->string != NULL)
			cdCmd(s->err->string);
		return shell_cd(s->params);
	}
	if ((s->verb->next_part != NULL)
		&& (equ(s->verb->next_part->string, "="))) {
		return envCmd(s->verb->string,
			s->verb->next_part->next_part->string);
	}

	np = fork();

	switch (np) {
	case -1:
		fail();
		break;
	case 0:
		fd = open(in, O_RDONLY);
		dup2(fd, STDIN_FILENO);
		close(fd);
		FLAG = getFlag(s->io_flags, IO_OUT_APPEND);
		fd = open(out, O_WRONLY | O_CREAT | FLAG, 0644);
		dup2(fd, STDOUT_FILENO);
		close(fd);
		FLAG = getFlag(s->io_flags, IO_ERR_APPEND);
		fd = open(err, O_WRONLY | O_CREAT | FLAG, 0644);
		if (err != NULL && out != NULL && equ(err, out))
			dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
		rc = execvp(cmd, argv);
		if (rc < 0) {
			free(argv);
			handler(cmd);
		}
		free(cmd);
		free(argv);
		exit(EXIT_SUCCESS);
		break;
	default:
		wp = waitpid(np, &stat, 0);
		rc = WEXITSTATUS(stat);
		break;
	}
	return rc;
}

static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t rez, ap, np;
	int stat;

	np = fork();
	switch (np) {
	case -1:
		fail();
	case 0:
		exit(parse_command(cmd1, level, father));
	default:
		ap = fork();
		switch (ap) {
		case -1:
			fail();
		case 0:
			exit(parse_command(cmd2, level, father));
		}
	rez = waitpid(ap, &stat, 0);
	DIE(rez < 0, "waitpid");
	rez = waitpid(np, &stat, 0);
	DIE(rez < 0, "waitpid");
	return WEXITSTATUS(stat) == 0 ? true : false;
	}
}

static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int d[2], stat, rez;
	pid_t np, ap;

	rez = pipe(d);
	DIE(rez < 0, "pipe");
	np = fork();
	switch (np) {
	case -1:
		fail();
	case 0:
		dup2(d[1], STDOUT_FILENO);
		closeDescriptors(d);
		exit(parse_command(cmd1, level + 1, father));
	default:
		ap = fork();
		switch (ap) {
		case -1:
			fail();
		case 0:
			dup2(d[0], STDIN_FILENO);
			closeDescriptors(d);
			exit(parse_command(cmd2, level + 1, father));
		}
	}
	waitpid(np, &stat, 0);
	closeDescriptors(d);
	waitpid(ap, &stat, 0);
	return WEXITSTATUS(stat);
}

int parse_command(command_t *c, int level, command_t *father)
{
	int rez = 0, final;

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);
	switch (c->op) {
	case OP_SEQUENTIAL:
		final = parse_command(c->cmd1, level + 1, father);
		final = parse_command(c->cmd2, level + 1, father);
		break;

	case OP_PARALLEL:
		final = do_in_parallel(c->cmd1, c->cmd2, level + 1, father);
		break;
	case OP_CONDITIONAL_NZERO:
	case OP_CONDITIONAL_ZERO:
		rez = parse_command(c->cmd1, level + 1, father);
		if ((rez == 0 && c->op == OP_CONDITIONAL_ZERO)
			|| (c->op == OP_CONDITIONAL_NZERO && rez != 0))
			final = parse_command(c->cmd2, level + 1, father);
		break;
	case OP_PIPE:
		final = do_on_pipe(c->cmd1, c->cmd2, level + 1, father);
		break;
	default:
		return shell_exit();
	}
	return final;
}
