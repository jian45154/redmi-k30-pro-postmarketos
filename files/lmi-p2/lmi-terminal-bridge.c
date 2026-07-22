/*
 * SPDX-License-Identifier: MIT
 *
 * Unprivileged bridge between weston-terminal and one contained shell PTY.
 * Stock weston-terminal does not expose compositor-authenticated text focus,
 * so this bridge intentionally has no OSK side channel.  Physical-keyboard
 * input arrives only on its inherited standard input.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "lmi-child-supervisor.h"

enum {
	BUFFER_SIZE = 4096,
	CHILD_STOP_ATTEMPTS = 30,
	BRIDGE_POLL_MS = 250,
	IO_DEADLINE_MS = 2000,
	STOP_INTERVAL_NANOSECONDS = 100000000,
};

#ifndef LMI_TERMINAL_SHELL
#define LMI_TERMINAL_SHELL "/bin/ash"
#endif

static volatile sig_atomic_t resize_requested;
static volatile sig_atomic_t stop_requested;

static void
handle_resize(int signal_number)
{
	(void)signal_number;
	resize_requested = 1;
}

static void
handle_stop(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static uint64_t
monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000) +
	       (uint64_t)now.tv_nsec / UINT64_C(1000000);
}

static int
set_nonblocking(int fd, int *original_flags)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	if (original_flags != NULL)
		*original_flags = flags;
	return 0;
}

static int
write_all_bounded(int fd, const uint8_t *buffer, size_t length)
{
	size_t offset = 0;
	uint64_t start = monotonic_milliseconds();

	while (offset < length) {
		ssize_t written = write(fd, buffer + offset, length - offset);

		if (written > 0) {
			offset += (size_t)written;
			continue;
		}
		if (written < 0 && errno == EINTR) {
			if (stop_requested)
				return -1;
			continue;
		}
		if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd output = { .fd = fd, .events = POLLOUT };
			uint64_t now = monotonic_milliseconds();
			int remaining;

			if (start == 0 || now == 0 || now - start >= IO_DEADLINE_MS) {
				errno = ETIMEDOUT;
				return -1;
			}
			remaining = (int)(IO_DEADLINE_MS - (now - start));
			if (poll(&output, 1, remaining) <= 0) {
				if (errno == EINTR && !stop_requested)
					continue;
				errno = ETIMEDOUT;
				return -1;
			}
			if (output.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				errno = EPIPE;
				return -1;
			}
			continue;
		}
		return -1;
	}
	return 0;
}

static int
copy_available(int source, int destination)
{
	uint8_t buffer[BUFFER_SIZE];
	ssize_t count;

	do {
		count = read(source, buffer, sizeof(buffer));
	} while (count < 0 && errno == EINTR && !stop_requested);
	if (count > 0)
		return write_all_bounded(destination, buffer, (size_t)count);
	if (count == 0)
		return 1;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;
	return -1;
}

static int
drain_shell(pid_t child, int fallback_status, bool use_child_status)
{
	const struct lmi_child_drain_policy policy = {
		.anchor = child,
		.signal_anchor = true,
		.graceful_signal = SIGHUP,
		.graceful_attempts = CHILD_STOP_ATTEMPTS,
		.force_signal = SIGKILL,
		.force_attempts = CHILD_STOP_ATTEMPTS,
		.interval_nanoseconds = STOP_INTERVAL_NANOSECONDS,
	};
	int child_status = 1;

	if (lmi_child_drain(&policy, NULL) < 0) {
		perror("shell process tree did not become empty before its deadline");
		return 1;
	}
	if (lmi_child_reap_anchor(child, &child_status) < 0) {
		perror("could not reap the retained shell anchor");
		return 1;
	}
	return use_child_status ? child_status : fallback_status;
}

static int
terminate_shell(pid_t child, int fallback_status)
{
	return drain_shell(child, fallback_status, false);
}

static int
drain_adopted_shell_children(pid_t child)
{
	const struct lmi_child_drain_policy policy = {
		.anchor = child,
		.signal_anchor = false,
		.graceful_signal = SIGHUP,
		.graceful_attempts = CHILD_STOP_ATTEMPTS,
		.force_signal = SIGKILL,
		.force_attempts = CHILD_STOP_ATTEMPTS,
		.interval_nanoseconds = STOP_INTERVAL_NANOSECONDS,
	};

	return lmi_child_drain(&policy, NULL);
}

static int
finish_shell(pid_t child)
{
	return drain_shell(child, 1, true);
}

static void
child_setup_failed(int master, int slave, int ready_fd)
	__attribute__((noreturn));

static void
child_setup_failed(int master, int slave, int ready_fd)
{
	if (master >= 0)
		close(master);
	if (slave > STDERR_FILENO)
		close(slave);
	if (ready_fd >= 0)
		close(ready_fd);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	_exit(126);
}

/* The duplicated descriptors are intentionally inherited as the shell's
 * standard streams across execl.  GCC's analyzer reports those three fixed
 * descriptors as leaks even though every execl failure reaches
 * child_setup_failed and closes them. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#endif
static int
spawn_shell(pid_t *child, const struct termios *settings)
{
	char slave_name[128];
	struct winsize size;
	struct pollfd ready_poll;
	uint8_t ready_byte;
	int ready[2] = { -1, -1 };
	int master = -1, slave;

	master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 ||
	    ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
		if (master >= 0)
			close(master);
		return -1;
	}
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0)
		(void)ioctl(master, TIOCSWINSZ, &size);
	if (pipe2(ready, O_CLOEXEC) < 0) {
		close(master);
		return -1;
	}
	*child = fork();
	if (*child < 0) {
		close(ready[0]);
		close(ready[1]);
		close(master);
		return -1;
	}
	if (*child == 0) {
		close(ready[0]);
		(void)signal(SIGHUP, SIG_DFL);
		(void)signal(SIGINT, SIG_DFL);
		(void)signal(SIGTERM, SIG_DFL);
		(void)signal(SIGWINCH, SIG_DFL);
		if (setsid() < 0)
			child_setup_failed(master, -1, ready[1]);
		slave = open(slave_name, O_RDWR | O_NOCTTY);
		if (slave < 0 || tcsetattr(slave, TCSANOW, settings) < 0 ||
		    ioctl(slave, TIOCSCTTY, 0) < 0 ||
		    dup2(slave, STDIN_FILENO) < 0 ||
		    dup2(slave, STDOUT_FILENO) < 0 ||
		    dup2(slave, STDERR_FILENO) < 0)
			child_setup_failed(master, slave, ready[1]);
		if (slave > STDERR_FILENO)
			close(slave);
		close(master);
		if (write(ready[1], "R", 1) != 1)
			child_setup_failed(-1, -1, ready[1]);
		close(ready[1]);
		execl(LMI_TERMINAL_SHELL, "ash", "-l", (char *)NULL);
		child_setup_failed(-1, -1, -1);
	}
	close(ready[1]);
	ready_poll.fd = ready[0];
	ready_poll.events = POLLIN;
	ready_poll.revents = 0;
	if (poll(&ready_poll, 1, IO_DEADLINE_MS) <= 0 ||
	    !(ready_poll.revents & POLLIN) ||
	    read(ready[0], &ready_byte, 1) != 1 || ready_byte != 'R') {
		int saved_errno = errno == 0 ? ETIMEDOUT : errno;

		close(ready[0]);
		close(master);
		(void)terminate_shell(*child, 1);
		errno = saved_errno;
		return -1;
	}
	close(ready[0]);
	if (set_nonblocking(master, NULL) < 0) {
		int saved_errno = errno;

		close(master);
		(void)terminate_shell(*child, 1);
		errno = saved_errno;
		return -1;
	}
	return master;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static void
copy_window_size(int terminal)
{
	struct winsize size;

	/* TIOCSWINSZ on the PTY notifies its actual foreground process group. */
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0)
		(void)ioctl(terminal, TIOCSWINSZ, &size);
}

static int
bridge_loop(int terminal, pid_t child)
{
	for (;;) {
		struct pollfd descriptors[2] = {
			{ .fd = STDIN_FILENO, .events = POLLIN },
			{ .fd = terminal, .events = POLLIN },
		};
		bool has_adopted = false;
		bool child_exited = false;
		int child_code;
		int changed;

		if (lmi_child_peek_exit_code(
			    child, &child_exited, &child_code) < 0) {
			perror("could not inspect the retained shell anchor");
			return terminate_shell(child, 1);
		}
		if (child_exited)
			return finish_shell(child);
		if (lmi_child_has_adopted(child, &has_adopted) < 0) {
			perror("could not inspect the owned shell process tree");
			return terminate_shell(child, 1);
		}
		if (has_adopted && drain_adopted_shell_children(child) < 0) {
			perror("could not drain an escaped shell descendant");
			return terminate_shell(child, 1);
		}
		if (stop_requested)
			return terminate_shell(child, 0);
		if (resize_requested) {
			resize_requested = 0;
			copy_window_size(terminal);
		}
		changed = poll(descriptors, 2, BRIDGE_POLL_MS);
		if (changed < 0) {
			if (errno == EINTR)
				continue;
			return terminate_shell(child, 1);
		}
		if (descriptors[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
			if (copy_available(STDIN_FILENO, terminal) != 0)
				return terminate_shell(child, 1);
		}
		if (descriptors[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
			if (copy_available(terminal, STDOUT_FILENO) != 0)
				return finish_shell(child);
		}
	}
}

static int
install_signal_handlers(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = handle_resize;
	if (sigaction(SIGWINCH, &action, NULL) < 0)
		return -1;
	action.sa_handler = handle_stop;
	if (sigaction(SIGHUP, &action, NULL) < 0 ||
	    sigaction(SIGINT, &action, NULL) < 0 ||
	    sigaction(SIGTERM, &action, NULL) < 0)
		return -1;
	return 0;
}

int
main(int argc, char **argv)
{
	struct termios original, raw;
	pid_t child;
	int terminal = -1;
	int stdin_flags = -1, stdout_flags = -1;
	int result = 1;

	(void)argv;
	if (argc != 1 || getuid() == 0 || geteuid() == 0) {
		fprintf(stderr, "lmi-terminal-bridge requires one unprivileged session\n");
		return 64;
	}
	if (install_signal_handlers() < 0) {
		perror("could not install terminal bridge signal handlers");
		return 1;
	}
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) ||
	    tcgetattr(STDIN_FILENO, &original) < 0) {
		fprintf(stderr, "lmi-terminal-bridge requires a terminal\n");
		return 1;
	}
	if (lmi_child_supervisor_enable() < 0) {
		perror("could not establish stable shell descendant ownership");
		return 1;
	}
	terminal = spawn_shell(&child, &original);
	if (terminal < 0) {
		perror("could not start the lmi shell PTY");
		return 1;
	}
	raw = original;
	cfmakeraw(&raw);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0 ||
	    set_nonblocking(STDIN_FILENO, &stdin_flags) < 0 ||
	    set_nonblocking(STDOUT_FILENO, &stdout_flags) < 0) {
		perror("could not enter bounded terminal bridge I/O mode");
		result = terminate_shell(child, 1);
		goto cleanup;
	}
	result = bridge_loop(terminal, child);

cleanup:
	if (stdin_flags >= 0)
		(void)fcntl(STDIN_FILENO, F_SETFL, stdin_flags);
	if (stdout_flags >= 0)
		(void)fcntl(STDOUT_FILENO, F_SETFL, stdout_flags);
	(void)tcsetattr(STDIN_FILENO, TCSANOW, &original);
	close(terminal);
	return result;
}
