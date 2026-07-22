/* SPDX-License-Identifier: MIT */
#include "lmi-layer-state.h"

void
lmi_layer_state_init(struct lmi_layer_state *state)
{
	state->requested = 0;
	state->displayed = 0;
	state->presented = false;
}

void
lmi_layer_state_request(struct lmi_layer_state *state, size_t layer)
{
	state->requested = layer;
}

bool
lmi_layer_state_should_present(const struct lmi_layer_state *state)
{
	return !state->presented || state->requested != state->displayed;
}

void
lmi_layer_state_mark_presented(struct lmi_layer_state *state)
{
	state->displayed = state->requested;
	state->presented = true;
}
