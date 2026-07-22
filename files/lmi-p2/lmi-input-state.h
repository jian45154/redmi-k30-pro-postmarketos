/* SPDX-License-Identifier: MIT */
#ifndef LMI_INPUT_STATE_H
#define LMI_INPUT_STATE_H

#include <stdbool.h>

/* Stock Weston 14 can authenticate input-method contexts created for native
 * text-input clients.  It cannot authenticate focus for weston-terminal, so
 * no terminal route exists in this state machine. */
enum lmi_input_route {
	LMI_INPUT_NONE,
	LMI_INPUT_EDITOR,
};

struct lmi_input_state {
	enum lmi_input_route route;
	bool context_active;
};

void lmi_input_state_init(struct lmi_input_state *state);
void lmi_input_state_context_activated(struct lmi_input_state *state);
void lmi_input_state_context_deactivated(struct lmi_input_state *state);

#endif
