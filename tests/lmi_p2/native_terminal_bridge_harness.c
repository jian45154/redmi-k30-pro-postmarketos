/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "lmi-child-supervisor.h"

struct child_report {
	pid_t pid;
	pid_t process_group;
	pid_t session;
	int kind;
};

static int
read_reports(int fd, struct child_report reports[2])
{
	size_t received = 0;

	while (received < sizeof(struct child_report) * 2) {
		struct pollfd descriptor = { .fd = fd, .events = POLLIN };
		ssize_t count;

		if (poll(&descriptor, 1, 2000) <= 0)
			return -1;
		count = read(fd, (uint8_t *)reports + received,
		             sizeof(struct child_report) * 2 - received);
		if (count <= 0)
			return -1;
		received += (size_t)count;
	}
	return 0;
}

static void
report_and_pause(int fd, int kind)
{
	struct child_report report;

	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	if ((kind == 1 && setpgid(0, 0) < 0) ||
	    (kind == 2 && setsid() < 0))
		_exit(91);
	report.pid = getpid();
	report.process_group = getpgrp();
	report.session = getsid(0);
	report.kind = kind;
	if (write(fd, &report, sizeof(report)) != (ssize_t)sizeof(report))
		_exit(92);
	close(fd);
	for (;;)
		pause();
}

static int
wait_for_anchor_and_adoption(pid_t anchor, int expected_code)
{
	struct timespec interval = { .tv_sec = 0, .tv_nsec = 10000000 };
	int attempt;

	for (attempt = 0; attempt < 200; attempt++) {
		bool adopted = false;
		bool exited = false;
		int code;

		if (lmi_child_peek_exit_code(anchor, &exited, &code) == 0 && exited &&
		    code == expected_code &&
		    lmi_child_has_adopted(anchor, &adopted) == 0 && adopted)
			return 0;
		(void)nanosleep(&interval, NULL);
	}
	return -1;
}

static struct lmi_child_drain_policy
policy_for(pid_t anchor, unsigned int attempts)
{
	struct lmi_child_drain_policy policy = {
		.anchor = anchor,
		.signal_anchor = true,
		.graceful_signal = SIGTERM,
		.graceful_attempts = attempts,
		.force_signal = SIGKILL,
		.force_attempts = attempts,
		.interval_nanoseconds = 10000000,
	};

	return policy;
}

static int
exercise_abnormal_multi_session_cleanup(void)
{
	struct child_report reports[2];
	struct lmi_child_drain_policy policy;
	int report_pipe[2];
	int code;
	pid_t anchor;

	if (pipe2(report_pipe, O_CLOEXEC) < 0)
		return 10;
	anchor = fork();
	if (anchor < 0) {
		close(report_pipe[0]);
		close(report_pipe[1]);
		return 11;
	}
	if (anchor == 0) {
		pid_t child;

		close(report_pipe[0]);
		if (setsid() < 0)
			_exit(90);
		child = fork();
		if (child == 0)
			report_and_pause(report_pipe[1], 1);
		if (child < 0)
			_exit(93);
		child = fork();
		if (child == 0)
			report_and_pause(report_pipe[1], 2);
		if (child < 0)
			_exit(94);
		close(report_pipe[1]);
		(void)kill(getpid(), SIGKILL);
		_exit(95);
	}
	close(report_pipe[1]);
	if (read_reports(report_pipe[0], reports) < 0)
		return 12;
	close(report_pipe[0]);
	if (wait_for_anchor_and_adoption(anchor, 128 + SIGKILL) < 0)
		return 13;
	if (!((reports[0].kind == 1 && reports[1].kind == 2) ||
	      (reports[0].kind == 2 && reports[1].kind == 1)))
		return 14;
	if (reports[0].process_group == reports[1].process_group ||
	    reports[0].session == reports[1].session)
		return 15;

	/* The anchor remains a waitable zombie, so its PID cannot be reused while
	 * descendants are still live. */
	errno = 0;
	if (lmi_child_reap_anchor(anchor, &code) != -1 || errno != EBUSY ||
	    kill(anchor, 0) < 0 || getpgid(anchor) != anchor)
		return 16;
	policy = policy_for(anchor, 20);
	policy.signal_anchor = false;
	if (lmi_child_drain(&policy, NULL) < 0)
		return 17;
	if (lmi_child_reap_anchor(anchor, &code) < 0 || code != 128 + SIGKILL)
		return 18;
	if ((kill(reports[0].pid, 0) == 0 || errno != ESRCH) ||
	    (kill(reports[1].pid, 0) == 0 || errno != ESRCH))
		return 19;
	return 0;
}

static int
refuse_signal(pid_t pid, int signal_number)
{
	(void)pid;
	(void)signal_number;
	errno = EPERM;
	return -1;
}

static int
ignore_signal(pid_t pid, int signal_number)
{
	(void)pid;
	(void)signal_number;
	return 0;
}

static int
exercise_signal_failure(lmi_child_signal_fn signal_process, int expected_errno)
{
	struct lmi_child_drain_policy policy;
	pid_t anchor = fork();
	int code;

	if (anchor < 0)
		return 30;
	if (anchor == 0) {
		for (;;)
			pause();
	}
	policy = policy_for(anchor, 1);
	errno = 0;
	if (lmi_child_drain(&policy, signal_process) != -1 ||
	    errno != expected_errno)
		return 31;
	errno = 0;
	if (lmi_child_reap_anchor(anchor, &code) != -1 || errno != EBUSY)
		return 32;
	policy = policy_for(anchor, 20);
	if (lmi_child_drain(&policy, NULL) < 0 ||
	    lmi_child_reap_anchor(anchor, &code) < 0 || code != 128 + SIGTERM)
		return 33;
	return 0;
}

int
main(void)
{
	int result;

	if (lmi_child_supervisor_enable() < 0)
		return 1;
	result = exercise_abnormal_multi_session_cleanup();
	if (result != 0)
		return result;
	result = exercise_signal_failure(refuse_signal, EPERM);
	if (result != 0)
		return result;
	return exercise_signal_failure(ignore_signal, ETIMEDOUT);
}
