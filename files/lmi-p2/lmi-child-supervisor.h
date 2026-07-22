/* SPDX-License-Identifier: MIT */
#ifndef LMI_CHILD_SUPERVISOR_H
#define LMI_CHILD_SUPERVISOR_H

#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>

typedef int (*lmi_child_signal_fn)(pid_t pid, int signal_number);

struct lmi_child_drain_policy {
	pid_t anchor;
	bool signal_anchor;
	int graceful_signal;
	unsigned int graceful_attempts;
	int force_signal;
	unsigned int force_attempts;
	long interval_nanoseconds;
};

int lmi_child_supervisor_enable(void);
int lmi_child_has_adopted(pid_t anchor, bool *has_adopted);
int lmi_child_peek_exit_code(pid_t anchor, bool *exited, int *code);
int lmi_child_drain(const struct lmi_child_drain_policy *policy,
	            lmi_child_signal_fn signal_process);
int lmi_child_reap_anchor(pid_t anchor, int *code);

#endif
