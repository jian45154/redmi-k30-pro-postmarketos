/*
 * SPDX-License-Identifier: MIT
 * Root-only, argument-free and bounded handoff from OpenRC to VT 7.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "lmi-child-supervisor.h"

enum {
	READY_WAIT_ATTEMPTS = 150,
	STOP_WAIT_ATTEMPTS = 50,
	WAIT_NANOSECONDS = 100000000,
};

static volatile sig_atomic_t stop_requested;

static void
handle_stop(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static bool
all_root_ids(void)
{
	uid_t real_id, effective_id, saved_id;

	if (getresuid(&real_id, &effective_id, &saved_id) < 0)
		return false;
	return real_id == 0 && effective_id == 0 && saved_id == 0;
}

static bool
is_character_device(const char *path)
{
	struct stat metadata;

	return lstat(path, &metadata) == 0 && S_ISCHR(metadata.st_mode);
}

static bool
seatd_socket_ready(void)
{
	struct stat metadata;

	return lstat("/run/seatd.sock", &metadata) == 0 &&
	       S_ISSOCK(metadata.st_mode);
}

static bool
drm_primary_ready(void)
{
	DIR *directory;
	struct dirent *entry;
	bool found = false;

	directory = opendir("/dev/dri");
	if (directory == NULL)
		return false;
	while ((entry = readdir(directory)) != NULL) {
		const char *cursor;
		char path[128];

		if (strncmp(entry->d_name, "card", 4) != 0)
			continue;
		cursor = entry->d_name + 4;
		if (*cursor == '\0')
			continue;
		while (*cursor >= '0' && *cursor <= '9')
			cursor++;
		if (*cursor != '\0')
			continue;
		if (snprintf(path, sizeof(path), "/dev/dri/%s", entry->d_name) < 0)
			continue;
		if (is_character_device(path)) {
			found = true;
			break;
		}
	}
	closedir(directory);
	return found;
}

static int
prepare_runtime(const struct passwd *account)
{
	int parent_fd = -1, runtime_fd = -1;
	char name[32];
	struct stat metadata;

	if (snprintf(name, sizeof(name), "%lu", (unsigned long)account->pw_uid) < 0)
		return -1;
	parent_fd = open("/run/user", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (parent_fd < 0 && errno == ENOENT) {
		if (mkdir("/run/user", 0755) < 0 && errno != EEXIST)
			return -1;
		parent_fd = open("/run/user", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	}
	if (parent_fd < 0)
		return -1;
	if (mkdirat(parent_fd, name, 0700) < 0 && errno != EEXIST)
		goto fail;
	runtime_fd = openat(parent_fd, name,
	                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (runtime_fd < 0 || fstat(runtime_fd, &metadata) < 0 ||
	    !S_ISDIR(metadata.st_mode))
		goto fail;
	if (metadata.st_uid != account->pw_uid && metadata.st_uid != 0) {
		errno = EPERM;
		goto fail;
	}
	if (fchown(runtime_fd, account->pw_uid, account->pw_gid) < 0 ||
	    fchmod(runtime_fd, 0700) < 0)
		goto fail;
	close(runtime_fd);
	close(parent_fd);
	return 0;

fail:
	if (runtime_fd >= 0)
		close(runtime_fd);
	close(parent_fd);
	return -1;
}

static int
install_signal_handlers(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = handle_stop;
	if (sigaction(SIGHUP, &action, NULL) < 0 ||
	    sigaction(SIGINT, &action, NULL) < 0 ||
	    sigaction(SIGTERM, &action, NULL) < 0)
		return -1;
	return 0;
}

static void
sleep_interval(const struct timespec *interval)
{
	struct timespec remaining = *interval;

	while (nanosleep(&remaining, &remaining) < 0 && errno == EINTR) {
		if (stop_requested)
			break;
	}
}

static pid_t
start_vt_session(void)
{
	pid_t child = fork();

	if (child != 0)
		return child;
	(void)signal(SIGHUP, SIG_DFL);
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGTERM, SIG_DFL);
	if (setsid() < 0) {
		perror("could not create the fixed VT session");
		_exit(126);
	}
	execl("/usr/bin/openvt", "openvt", "-e", "-c", "7", "-s", "--",
	      "/usr/libexec/lmi-p2/lmi-session-launcher", (char *)NULL);
	perror("could not execute the fixed openvt handoff");
	_exit(126);
}

static int
drain_children(pid_t anchor, bool signal_anchor)
{
	const struct lmi_child_drain_policy policy = {
		.anchor = anchor,
		.signal_anchor = signal_anchor,
		.graceful_signal = SIGTERM,
		.graceful_attempts = STOP_WAIT_ATTEMPTS,
		.force_signal = SIGKILL,
		.force_attempts = STOP_WAIT_ATTEMPTS,
		.interval_nanoseconds = WAIT_NANOSECONDS,
	};

	return lmi_child_drain(&policy, NULL);
}

static int
wait_for_session(pid_t child, const struct timespec *interval)
{
	int child_code = 1;
	bool child_exited = false;
	bool supervision_failed = false;

	for (;;) {
		bool has_adopted = false;

		if (lmi_child_peek_exit_code(
			    child, &child_exited, &child_code) < 0) {
			perror("could not inspect the retained VT anchor");
			supervision_failed = true;
			break;
		}
		if (lmi_child_has_adopted(child, &has_adopted) < 0) {
			perror("could not inspect the owned VT process tree");
			supervision_failed = true;
			break;
		}
		if (has_adopted && drain_children(child, false) < 0) {
			perror("could not drain an escaped VT descendant");
			supervision_failed = true;
			break;
		}
		if (child_exited || stop_requested)
			break;
		sleep_interval(interval);
	}

	/* Keep the direct child as an unreaped zombie while descendants are
	 * signalled and adopted.  That pins its PID and makes PID/PGID reuse
	 * irrelevant.  A descendant that calls setsid is still reparented to this
	 * subreaper when its parent exits. */
	if (drain_children(child, !child_exited) < 0) {
		perror("VT process tree did not become empty before its deadline");
		return 1;
	}
	if (lmi_child_reap_anchor(child, &child_code) < 0) {
		perror("could not reap the retained VT anchor");
		return 1;
	}
	if (supervision_failed)
		return 1;
	if (stop_requested)
		return 0;
	return child_code;
}

int
main(int argc, char **argv)
{
	struct passwd *account;
	struct timespec interval = { .tv_sec = 0, .tv_nsec = WAIT_NANOSECONDS };
	pid_t child;
	int attempt;

	(void)argv;
	if (argc != 1) {
		fprintf(stderr, "lmi-display-handoff accepts no arguments\n");
		return 64;
	}
	if (!all_root_ids()) {
		fprintf(stderr, "lmi-display-handoff requires real/effective/saved root\n");
		return 77;
	}
	if (install_signal_handlers() < 0) {
		perror("could not install display handoff signal handlers");
		return 1;
	}
	if (lmi_child_supervisor_enable() < 0) {
		perror("could not enable stable child supervision");
		return 1;
	}
	errno = 0;
	account = getpwnam("lmi-p2-gui");
	if (account == NULL || account->pw_uid == 0 || account->pw_gid == 0) {
		fprintf(stderr, "the fixed non-root GUI account is unavailable\n");
		return 78;
	}
	if (prepare_runtime(account) < 0) {
		perror("could not prepare the GUI runtime directory");
		return 78;
	}

	for (attempt = 0; attempt < READY_WAIT_ATTEMPTS && !stop_requested; attempt++) {
		if (is_character_device("/dev/tty0") &&
		    is_character_device("/dev/tty7") &&
		    seatd_socket_ready() && drm_primary_ready())
			break;
		sleep_interval(&interval);
	}
	if (stop_requested)
		return 0;
	if (attempt == READY_WAIT_ATTEMPTS) {
		fprintf(stderr,
		        "timed out after 15 seconds waiting for VT, seatd and DRM\n");
		return 75;
	}

	child = start_vt_session();
	if (child < 0) {
		perror("could not fork the fixed VT handoff");
		return 1;
	}
	return wait_for_session(child, &interval);
}
