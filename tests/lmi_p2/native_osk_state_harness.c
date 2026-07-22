/* SPDX-License-Identifier: MIT */
#include "lmi-input-state.h"
#include "lmi-layer-state.h"

int
main(void)
{
	struct lmi_input_state input;
	struct lmi_layer_state layer;

	lmi_input_state_init(&input);
	if (input.route != LMI_INPUT_NONE || input.context_active)
		return 1;
	lmi_input_state_context_activated(&input);
	if (input.route != LMI_INPUT_EDITOR || !input.context_active)
		return 2;
	lmi_input_state_context_deactivated(&input);
	if (input.route != LMI_INPUT_NONE || input.context_active)
		return 3;
	lmi_input_state_context_activated(&input);
	if (input.route != LMI_INPUT_EDITOR || !input.context_active)
		return 4;

	/* A released buffer is not recommitted unless the requested layer actually
	 * differs from the displayed layer. */
	lmi_layer_state_init(&layer);
	if (!lmi_layer_state_should_present(&layer))
		return 5;
	lmi_layer_state_mark_presented(&layer);
	if (lmi_layer_state_should_present(&layer))
		return 6;
	lmi_layer_state_request(&layer, 0);
	if (lmi_layer_state_should_present(&layer))
		return 7;
	lmi_layer_state_request(&layer, 1);
	if (!lmi_layer_state_should_present(&layer))
		return 8;
	lmi_layer_state_mark_presented(&layer);
	if (lmi_layer_state_should_present(&layer))
		return 9;

	return 0;
}
