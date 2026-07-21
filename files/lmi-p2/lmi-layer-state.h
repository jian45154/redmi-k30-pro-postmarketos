/* SPDX-License-Identifier: MIT */
#ifndef LMI_LAYER_STATE_H
#define LMI_LAYER_STATE_H

#include <stdbool.h>
#include <stddef.h>

struct lmi_layer_state {
	size_t requested;
	size_t displayed;
	bool presented;
};

void lmi_layer_state_init(struct lmi_layer_state *state);
void lmi_layer_state_request(struct lmi_layer_state *state, size_t layer);
bool lmi_layer_state_should_present(const struct lmi_layer_state *state);
void lmi_layer_state_mark_presented(struct lmi_layer_state *state);

#endif
