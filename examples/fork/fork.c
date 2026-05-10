/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* Build the whole log line into a stack buffer and emit it with a
 * single write(2). Avoids the per-chunk writes that fprintf may issue
 * (which interleave between parent and child on the shared stderr fd). */
static void dbg_emit(const char *func, int line, const char *fmt, ...) {
	char buf[512];
	va_list ap;
	int n, m;

	n = snprintf(buf, sizeof(buf), "[%s:%d] ", func, line);
	if (n < 0)
		n = 0;
	if ((size_t)n > sizeof(buf))
		n = sizeof(buf);

	va_start(ap, fmt);
	m = vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
	va_end(ap);
	if (m < 0)
		m = 0;
	n += m;
	if ((size_t)n > sizeof(buf))
		n = sizeof(buf);

	write(1, buf, (size_t)n);
}

#define DBG(...) dbg_emit(__func__, __LINE__, __VA_ARGS__)
#define DIE(...) \
	do { \
		dbg_emit(__func__, __LINE__, __VA_ARGS__); \
		_exit(0); \
	} while (0)

/**
 * @brief Prints the terminated reason
 * @param wstatus Status code.
 */
static void print_terminated_reason(int wstatus) {
	if (WIFEXITED(wstatus))
		DBG(" -> Reason: normally exited, code: %d\n", WEXITSTATUS(wstatus));
	else if (WIFSIGNALED(wstatus))
		DBG(" -> Reason: received signal: %d\n", WTERMSIG(wstatus));
	else if (WIFSTOPPED(wstatus))
		DBG(" -> Reason: stopped, status: %d\n", WSTOPSIG(wstatus));
	else
		DBG(" -> Reason: unknown wstatus: 0x%x\n", wstatus);
}

/* Checks if a simple fork+wait works as expected. */
static void test_wait(void) {
	pid_t pid;
	if ((pid = fork()) > 0) {
		wait(NULL);
		DBG("Father process\n");
	}
	else if (pid == 0) {
		DBG("Child process\n");
		_exit(0);
	}
	else {
		DBG("Unable to fork, error: (%s)\n", strerror(errno));
		_exit(1);
	}
	DBG("Father process, post-child death!\n");
}

/* Tests a normally ended child and retrieves its return code. */
static void test_wait_normal_status(void) {
	pid_t pid;
	int wstatus;
	if ((pid = fork()) > 0) {
		wait(&wstatus);
		DBG("Father process\n");
		print_terminated_reason(wstatus);
	}
	else if (pid == 0) {
		DBG("Child process\n");
		_exit(1);
	}
	else {
		DBG("Unable to fork, error: (%s)\n", strerror(errno));
		_exit(1);
	}
}

/* Checks if a child killed by a signal is handled properly. */
static void test_wait_signal_status(void) {
	pid_t pid;
	int wstatus;
	if ((pid = fork()) > 0) {
		wait(&wstatus);
		DBG("Father process\n");
		print_terminated_reason(wstatus);
	}
	else if (pid == 0) {
		DBG("Child process, killing myself\n");
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	else {
		DBG("Unable to fork, error: (%s)\n", strerror(errno));
		_exit(1);
	}
}

/* Checks the returned 'rusage' if it is filled properly. */
static void test_wait_rusage(void)
{
	struct rusage ru;
	int wstatus;
	pid_t pid;
	char *p;

	if ((pid = fork()) > 0) {
		wait3(&wstatus, 0, &ru);
		DBG("Father process\n");
		print_terminated_reason(wstatus);

		/* Print child usage. */
		DBG("-> Child mem: >= 64 MiB (%d)\n", ru.ru_maxrss >= (64<<10));
	}
	else if (pid == 0) {
		DBG("Child process, killing myself\n");
		/* Waste some memory. */
		if (!(p = malloc(64<<20)))
			DIE("Unable to allocate 64MiB!, aborting...\n");
		memset(p, 0xFF, 64<<20);
		free(p);
		_exit(5);
	}
	else {
		DBG("Unable to fork, error: (%s)\n", strerror(errno));
		_exit(1);
	}
}

/* Asserts the return code for a process that have no child to
 * wait for. */
static void test_nochild(void) {
	pid_t pid = wait(NULL);
	DBG("pid: %d, errno: (%s)\n", pid, strerror(errno));
}

/* Asserts if WNOHANG option flag works. */
static void test_nohang(void)
{
	int p[2];
	pid_t w;
	pid_t pid;
	int wstatus;
	char c;

	if (pipe(p) < 0) {
		DBG("pipe failed: (%s)\n", strerror(errno));
		return;
	}

	pid = fork();
	if (pid < 0) {
		DBG("Unable to fork, error: (%s)\n", strerror(errno));
		close(p[0]);
		close(p[1]);
		return;
	}

	if (pid == 0) {
		close(p[1]);
		read(p[0], &c, 1);
		close(p[0]);
		DBG("Child exiting\n");
		_exit(0);
	}

	/* Parent: child is guaranteed alive and blocked on read(). */
	close(p[0]);
	w = waitpid(pid, &wstatus, WNOHANG);
	DBG("WNOHANG while child alive: returned %d (expected 0)\n", w);

	/* Release child, then reap with a blocking wait. */
	close(p[1]);
	w = waitpid(pid, &wstatus, 0);
	DBG("blocking wait after release: returned == expected? (%d)\n", (w==pid));
	print_terminated_reason(wstatus);
}

/* Asserts WNOHANG returns the pid once the child has actually exited. */
static void test_nohang_exited(void) {
	pid_t pid, w;
	int wstatus;

	pid = fork();
	if (pid < 0) {
		DBG("Unable to fork, error: (%s)\n", strerror(errno));
		return;
	}
	if (pid == 0)
		_exit(7);

	/* Poll until the kernel reports the child as exited. The first
	 * iteration may return 0 if the child has not yet been reaped.
	 */
	do {
		w = waitpid(pid, &wstatus, WNOHANG);
	} while (w == 0);

	DBG("WNOHANG after child exited: returned == expected (%d)\n", (w==pid));
	print_terminated_reason(wstatus);
}

int main(void)
{
	test_wait();
	test_wait_normal_status();
	test_wait_signal_status();
	test_wait_rusage();
	test_nochild();
	test_nohang();
	test_nohang_exited();
	return 0;
}
