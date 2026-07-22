/*
 * SPDX-License-Identifier: MIT
 * Fixed root-to-dedicated-GUI privilege boundary for the Weston session.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define LMI_ACCOUNT "lmi-p2-gui"
#define LMI_ACCOUNT_HOME "/var/lib/lmi-p2/home"
#define LMI_ACCOUNT_SHELL "/bin/false"
#define LMI_SEAT_GROUP "seat"
#define LMI_USER_SESSION "/usr/libexec/lmi-p2/lmi-weston-user-session"

static bool
all_root_ids(void)
{
	uid_t real_id, effective_id, saved_id;
	gid_t real_group, effective_group, saved_group;

	if (getresuid(&real_id, &effective_id, &saved_id) < 0 ||
	    getresgid(&real_group, &effective_group, &saved_group) < 0)
		return false;
	return real_id == 0 && effective_id == 0 && saved_id == 0 &&
	       real_group == 0 && effective_group == 0 && saved_group == 0;
}

static bool
group_contains_user(const struct group *group, const char *name)
{
	char *const *member;

	for (member = group->gr_mem; member != NULL && *member != NULL; member++) {
		if (strcmp(*member, name) == 0)
			return true;
	}
	return false;
}

static bool
only_seat_is_supplementary(gid_t seat_group)
{
	gid_t groups[2];
	int count = getgroups(2, groups);

	return count == 1 && groups[0] == seat_group;
}

static bool
clear_and_verify_capabilities(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct capabilities[2] = { { 0 } };
	size_t index;

	if (syscall(SYS_capset, &header, capabilities) < 0)
		return false;
	memset(capabilities, 0xff, sizeof(capabilities));
	if (syscall(SYS_capget, &header, capabilities) < 0)
		return false;
	for (index = 0; index < 2; index++) {
		if (capabilities[index].effective != 0 ||
		    capabilities[index].permitted != 0 ||
		    capabilities[index].inheritable != 0)
			return false;
	}
	return true;
}

int
main(int argc, char **argv)
{
	const struct passwd *account;
	const struct group *seat;
	gid_t seat_group;
	gid_t primary_group;
	uid_t user_id;
	uid_t real_id, effective_id, saved_id;
	gid_t real_group, effective_group, saved_group;

	(void)argv;
	if (argc != 1) {
		fprintf(stderr, "lmi-session-launcher accepts no arguments\n");
		return 64;
	}
	if (!all_root_ids()) {
		fprintf(stderr, "lmi-session-launcher requires real/effective/saved root\n");
		return 77;
	}
	account = getpwnam(LMI_ACCOUNT);
	if (account == NULL || account->pw_uid == 0 || account->pw_gid == 0 ||
	    strcmp(account->pw_dir, LMI_ACCOUNT_HOME) != 0 ||
	    strcmp(account->pw_shell, LMI_ACCOUNT_SHELL) != 0) {
		fprintf(stderr, "the fixed GUI-only account is unavailable\n");
		return 78;
	}
	user_id = account->pw_uid;
	primary_group = account->pw_gid;
	seat = getgrnam(LMI_SEAT_GROUP);
	if (seat == NULL || seat->gr_gid == 0 ||
	    !group_contains_user(seat, LMI_ACCOUNT)) {
		fprintf(stderr, "the fixed GUI-only account/seat membership is unavailable\n");
		return 78;
	}
	seat_group = seat->gr_gid;

	/* Do not inherit root's group vector.  The session receives exactly the
	 * one supplementary group needed to authenticate to seatd. */
	if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0 ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 ||
	    setgroups(1, &seat_group) < 0 ||
	    setresgid(primary_group, primary_group, primary_group) < 0 ||
	    setresuid(user_id, user_id, user_id) < 0) {
		perror("could not enter the fixed GUI-only identity");
		return 77;
	}
	if (getresuid(&real_id, &effective_id, &saved_id) < 0 ||
	    getresgid(&real_group, &effective_group, &saved_group) < 0 ||
	    real_id != user_id || effective_id != user_id || saved_id != user_id ||
	    real_group != primary_group || effective_group != primary_group ||
	    saved_group != primary_group ||
	    !only_seat_is_supplementary(seat_group)) {
		fprintf(stderr, "GUI identity/group verification failed after privilege drop\n");
		return 77;
	}
	if (!clear_and_verify_capabilities()) {
		fprintf(stderr, "GUI capability verification failed after privilege drop\n");
		return 77;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("could not disable future privilege acquisition");
		return 77;
	}
	if (clearenv() < 0 || setenv("HOME", LMI_ACCOUNT_HOME, 1) < 0 ||
	    setenv("USER", LMI_ACCOUNT, 1) < 0 ||
	    setenv("LOGNAME", LMI_ACCOUNT, 1) < 0 ||
	    setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1) < 0 || chdir("/") < 0) {
		perror("could not construct the fixed GUI session environment");
		return 78;
	}

	execl(LMI_USER_SESSION, "lmi-weston-user-session", (char *)NULL);
	perror("could not execute the fixed lmi user session");
	return 126;
}
