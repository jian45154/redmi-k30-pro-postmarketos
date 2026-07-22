/*
 * SPDX-License-Identifier: MIT
 *
 * Linux 4.19 predates pidfd process ownership.  These single-threaded
 * launchers instead become child subreapers and enumerate only their direct
 * children.  Exited children stay waitable, pinning their PIDs, until every
 * descendant (including a new session or process group) has been adopted and
 * drained.  The caller's anchor is always reaped separately and last.
 */
#define _GNU_SOURCE

#include "lmi-child-supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct child_record {
	pid_t pid;
	char state;
};

struct child_snapshot {
	struct child_record *records;
	size_t count;
};

static void
snapshot_release(struct child_snapshot *snapshot)
{
	free(snapshot->records);
	snapshot->records = NULL;
	snapshot->count = 0;
}

static int
read_all(int descriptor, char **payload, size_t *length)
{
	size_t capacity = 256;
	char *buffer = malloc(capacity);

	if (buffer == NULL)
		return -1;
	*length = 0;
	for (;;) {
		ssize_t count;

		if (*length == capacity) {
			char *expanded;

			if (capacity >= 1024 * 1024) {
				free(buffer);
				errno = E2BIG;
				return -1;
			}
			capacity *= 2;
			expanded = realloc(buffer, capacity);
			if (expanded == NULL) {
				free(buffer);
				return -1;
			}
			buffer = expanded;
		}
		count = read(descriptor, buffer + *length, capacity - *length);
		if (count > 0) {
			*length += (size_t)count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0) {
			free(buffer);
			return -1;
		}
		break;
	}
	if (*length == capacity) {
		char *expanded = realloc(buffer, capacity + 1);

		if (expanded == NULL) {
			free(buffer);
			return -1;
		}
		buffer = expanded;
	}
	buffer[*length] = '\0';
	*payload = buffer;
	return 0;
}

static int
read_child_state(pid_t pid, char *state)
{
	char path[64];
	char buffer[4096];
	char *closing;
	long parsed_pid, parent, group, session;
	ssize_t count;
	int descriptor;

	if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) < 0) {
		errno = EINVAL;
		return -1;
	}
	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		return -1;
	count = pread(descriptor, buffer, sizeof(buffer) - 1, 0);
	close(descriptor);
	if (count <= 0)
		return -1;
	buffer[count] = '\0';
	parsed_pid = strtol(buffer, NULL, 10);
	closing = strrchr(buffer, ')');
	if (parsed_pid != pid || closing == NULL ||
	    sscanf(closing + 1, " %c %ld %ld %ld",
	           state, &parent, &group, &session) != 4) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int
snapshot_take(struct child_snapshot *snapshot)
{
	char path[96];
	char *payload = NULL;
	char *cursor;
	size_t payload_length = 0;
	size_t capacity = 0;
	int descriptor;

	snapshot->records = NULL;
	snapshot->count = 0;
	if (snprintf(path, sizeof(path), "/proc/self/task/%ld/children",
	             (long)getpid()) < 0) {
		errno = EINVAL;
		return -1;
	}
	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		return -1;
	if (read_all(descriptor, &payload, &payload_length) < 0) {
		close(descriptor);
		return -1;
	}
	close(descriptor);
	cursor = payload;
	while ((size_t)(cursor - payload) < payload_length) {
		char *end;
		long value;
		struct child_record *expanded;

		while (*cursor == ' ' || *cursor == '\n' || *cursor == '\t')
			cursor++;
		if (*cursor == '\0')
			break;
		errno = 0;
		value = strtol(cursor, &end, 10);
		if (errno != 0 || end == cursor || value <= 0 || value > INT_MAX) {
			errno = EPROTO;
			goto fail;
		}
		if (snapshot->count == capacity) {
			capacity = capacity == 0 ? 8 : capacity * 2;
			expanded = realloc(snapshot->records,
			                   capacity * sizeof(*snapshot->records));
			if (expanded == NULL)
				goto fail;
			snapshot->records = expanded;
		}
		snapshot->records[snapshot->count].pid = (pid_t)value;
		if (read_child_state((pid_t)value,
		                     &snapshot->records[snapshot->count].state) < 0)
			goto fail;
		snapshot->count++;
		cursor = end;
	}
	free(payload);
	return 0;

fail:
	free(payload);
	snapshot_release(snapshot);
	return -1;
}

static bool
is_exited(char state)
{
	return state == 'Z' || state == 'X' || state == 'x';
}

static int
default_signal_process(pid_t pid, int signal_number)
{
	return kill(pid, signal_number);
}

static void
sleep_interval(long nanoseconds)
{
	struct timespec interval = {
		.tv_sec = nanoseconds / 1000000000L,
		.tv_nsec = nanoseconds % 1000000000L,
	};

	while (nanosleep(&interval, &interval) < 0 && errno == EINTR)
		;
}

static int
reap_non_anchor_zombies(const struct child_snapshot *snapshot, pid_t anchor)
{
	size_t index;

	for (index = 0; index < snapshot->count; index++) {
		int status;
		pid_t result;

		if (snapshot->records[index].pid == anchor ||
		    !is_exited(snapshot->records[index].state))
			continue;
		do {
			result = waitpid(snapshot->records[index].pid, &status, WNOHANG);
		} while (result < 0 && errno == EINTR);
		if (result != snapshot->records[index].pid) {
			errno = ECHILD;
			return -1;
		}
	}
	return 0;
}

int
lmi_child_supervisor_enable(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGCHLD, &action, NULL) < 0 ||
	    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0)
		return -1;
	return 0;
}

int
lmi_child_has_adopted(pid_t anchor, bool *has_adopted)
{
	struct child_snapshot snapshot;
	bool anchor_found = false;
	size_t index;

	if (anchor <= 0 || has_adopted == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (snapshot_take(&snapshot) < 0)
		return -1;
	*has_adopted = false;
	for (index = 0; index < snapshot.count; index++) {
		if (snapshot.records[index].pid == anchor)
			anchor_found = true;
		else
			*has_adopted = true;
	}
	snapshot_release(&snapshot);
	if (!anchor_found) {
		errno = ECHILD;
		return -1;
	}
	return 0;
}

int
lmi_child_peek_exit_code(pid_t anchor, bool *exited, int *code)
{
	siginfo_t information;

	if (anchor <= 0 || exited == NULL || code == NULL) {
		errno = EINVAL;
		return -1;
	}
	*exited = false;
	memset(&information, 0, sizeof(information));
	while (waitid(P_PID, (id_t)anchor, &information,
	              WEXITED | WNOHANG | WNOWAIT) < 0) {
		if (errno != EINTR)
			return -1;
	}
	if (information.si_pid == 0)
		return 0;
	if (information.si_pid != anchor) {
		errno = EPROTO;
		return -1;
	}
	if (information.si_code == CLD_EXITED)
		*code = information.si_status;
	else
		*code = 128 + information.si_status;
	*exited = true;
	return 0;
}

int
lmi_child_drain(const struct lmi_child_drain_policy *policy,
	        lmi_child_signal_fn signal_process)
{
	int phases[2];
	unsigned int attempts[2];
	int last_signal_error = 0;
	int phase;

	if (policy == NULL || policy->anchor <= 0 ||
	    policy->interval_nanoseconds < 0) {
		errno = EINVAL;
		return -1;
	}
	if (signal_process == NULL)
		signal_process = default_signal_process;
	phases[0] = policy->graceful_signal;
	phases[1] = policy->force_signal;
	attempts[0] = policy->graceful_attempts;
	attempts[1] = policy->force_attempts;
	for (phase = 0; phase < 2; phase++) {
		unsigned int attempt;

		for (attempt = 0; attempt < attempts[phase]; attempt++) {
			struct child_snapshot snapshot;
			bool anchor_found = false;
			bool relevant_live = false;
			size_t index;

			if (snapshot_take(&snapshot) < 0)
				return -1;
			for (index = 0; index < snapshot.count; index++) {
				pid_t pid = snapshot.records[index].pid;
				bool should_signal = pid != policy->anchor ||
					policy->signal_anchor;

				if (pid == policy->anchor)
					anchor_found = true;
				if (is_exited(snapshot.records[index].state) ||
				    !should_signal)
					continue;
				relevant_live = true;
				if (signal_process(pid, phases[phase]) < 0 &&
				    errno != ESRCH)
					last_signal_error = errno;
			}
			if (!anchor_found) {
				snapshot_release(&snapshot);
				errno = ECHILD;
				return -1;
			}
			if (!relevant_live) {
				if (reap_non_anchor_zombies(
					    &snapshot, policy->anchor) < 0) {
					snapshot_release(&snapshot);
					return -1;
				}
				snapshot_release(&snapshot);
				if (lmi_child_has_adopted(
					    policy->anchor, &relevant_live) < 0)
					return -1;
				if (!relevant_live) {
					if (!policy->signal_anchor)
						return 0;
					{
						bool anchor_exited;
						int ignored_code;

						if (lmi_child_peek_exit_code(
							    policy->anchor, &anchor_exited,
							    &ignored_code) < 0)
							return -1;
						if (anchor_exited)
							return 0;
					}
				}
			} else {
				snapshot_release(&snapshot);
			}
			sleep_interval(policy->interval_nanoseconds);
		}
	}
	errno = last_signal_error != 0 ? last_signal_error : ETIMEDOUT;
	return -1;
}

int
lmi_child_reap_anchor(pid_t anchor, int *code)
{
	struct child_snapshot snapshot;
	int status;
	pid_t result;

	if (anchor <= 0 || code == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (snapshot_take(&snapshot) < 0)
		return -1;
	if (snapshot.count != 1 || snapshot.records[0].pid != anchor ||
	    !is_exited(snapshot.records[0].state)) {
		snapshot_release(&snapshot);
		errno = EBUSY;
		return -1;
	}
	snapshot_release(&snapshot);
	do {
		result = waitpid(anchor, &status, 0);
	} while (result < 0 && errno == EINTR);
	if (result != anchor)
		return -1;
	if (WIFEXITED(status))
		*code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		*code = 128 + WTERMSIG(status);
	else
		*code = 1;
	return 0;
}
