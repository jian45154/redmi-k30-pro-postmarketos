/* SPDX-License-Identifier: MIT */
#include "lmi-input-state.h"

void
lmi_input_state_init(struct lmi_input_state *state)
{
	state->route = LMI_INPUT_NONE;
	state->context_active = false;
}

void
lmi_input_state_context_activated(struct lmi_input_state *state)
{
	state->context_active = true;
	state->route = LMI_INPUT_EDITOR;
}

void
lmi_input_state_context_deactivated(struct lmi_input_state *state)
{
	state->context_active = false;
	state->route = LMI_INPUT_NONE;
}
