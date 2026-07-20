#ifndef LMI_TEST_INPUT_METHOD_PROTOCOL_H
#define LMI_TEST_INPUT_METHOD_PROTOCOL_H

#include <wayland-client.h>

struct zwp_input_method_v1;
struct zwp_input_method_context_v1;
struct zwp_input_panel_v1;
struct zwp_input_panel_surface_v1;

struct zwp_input_method_context_v1_listener {
	void (*surrounding_text)(void *, struct zwp_input_method_context_v1 *,
	                         const char *, uint32_t, uint32_t);
	void (*reset)(void *, struct zwp_input_method_context_v1 *);
	void (*content_type)(void *, struct zwp_input_method_context_v1 *,
	                     uint32_t, uint32_t);
	void (*invoke_action)(void *, struct zwp_input_method_context_v1 *,
	                     uint32_t, uint32_t);
	void (*commit_state)(void *, struct zwp_input_method_context_v1 *, uint32_t);
	void (*preferred_language)(void *, struct zwp_input_method_context_v1 *,
	                           const char *);
};

struct zwp_input_method_v1_listener {
	void (*activate)(void *, struct zwp_input_method_v1 *,
	                 struct zwp_input_method_context_v1 *);
	void (*deactivate)(void *, struct zwp_input_method_v1 *,
	                   struct zwp_input_method_context_v1 *);
};

#define ZWP_INPUT_PANEL_SURFACE_V1_POSITION_CENTER_BOTTOM 1

extern const struct wl_interface zwp_input_method_v1_interface;
extern const struct wl_interface zwp_input_panel_v1_interface;

void zwp_input_method_context_v1_keysym(
	struct zwp_input_method_context_v1 *, uint32_t, uint32_t, uint32_t,
	uint32_t, uint32_t);
void zwp_input_method_context_v1_commit_string(
	struct zwp_input_method_context_v1 *, uint32_t, const char *);
void zwp_input_method_context_v1_destroy(struct zwp_input_method_context_v1 *);
int zwp_input_method_context_v1_add_listener(
	struct zwp_input_method_context_v1 *,
	const struct zwp_input_method_context_v1_listener *, void *);
void zwp_input_method_context_v1_modifiers_map(
	struct zwp_input_method_context_v1 *, struct wl_array *);
int zwp_input_method_v1_add_listener(
	struct zwp_input_method_v1 *, const struct zwp_input_method_v1_listener *, void *);
struct zwp_input_panel_surface_v1 *zwp_input_panel_v1_get_input_panel_surface(
	struct zwp_input_panel_v1 *, struct wl_surface *);
void zwp_input_panel_surface_v1_set_toplevel(
	struct zwp_input_panel_surface_v1 *, struct wl_output *, uint32_t);

#endif
