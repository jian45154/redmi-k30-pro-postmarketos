#ifndef LMI_TEST_TEXT_INPUT_PROTOCOL_H
#define LMI_TEST_TEXT_INPUT_PROTOCOL_H

#include <wayland-client.h>

struct zwp_text_input_manager_v1;
struct zwp_text_input_v1;

struct zwp_text_input_v1_listener {
	void (*enter)(void *, struct zwp_text_input_v1 *, struct wl_surface *);
	void (*leave)(void *, struct zwp_text_input_v1 *);
	void (*modifiers_map)(void *, struct zwp_text_input_v1 *, struct wl_array *);
	void (*input_panel_state)(void *, struct zwp_text_input_v1 *, uint32_t);
	void (*preedit_string)(void *, struct zwp_text_input_v1 *, uint32_t,
	                      const char *, const char *);
	void (*preedit_styling)(void *, struct zwp_text_input_v1 *, uint32_t,
	                       uint32_t, uint32_t);
	void (*preedit_cursor)(void *, struct zwp_text_input_v1 *, int32_t);
	void (*commit_string)(void *, struct zwp_text_input_v1 *, uint32_t,
	                     const char *);
	void (*cursor_position)(void *, struct zwp_text_input_v1 *, int32_t, int32_t);
	void (*delete_surrounding_text)(void *, struct zwp_text_input_v1 *,
	                               int32_t, uint32_t);
	void (*keysym)(void *, struct zwp_text_input_v1 *, uint32_t, uint32_t,
	               uint32_t, uint32_t, uint32_t);
	void (*language)(void *, struct zwp_text_input_v1 *, uint32_t, const char *);
	void (*text_direction)(void *, struct zwp_text_input_v1 *, uint32_t, uint32_t);
};

extern const struct wl_interface zwp_text_input_manager_v1_interface;

struct zwp_text_input_v1 *zwp_text_input_manager_v1_create_text_input(
	struct zwp_text_input_manager_v1 *);
int zwp_text_input_v1_add_listener(
	struct zwp_text_input_v1 *, const struct zwp_text_input_v1_listener *, void *);
void zwp_text_input_v1_activate(
	struct zwp_text_input_v1 *, struct wl_seat *, struct wl_surface *);
void zwp_text_input_v1_deactivate(struct zwp_text_input_v1 *, struct wl_seat *);
void zwp_text_input_v1_show_input_panel(struct zwp_text_input_v1 *);
void zwp_text_input_v1_hide_input_panel(struct zwp_text_input_v1 *);
void zwp_text_input_v1_set_surrounding_text(
	struct zwp_text_input_v1 *, const char *, uint32_t, uint32_t);
void zwp_text_input_v1_commit_state(struct zwp_text_input_v1 *, uint32_t);

#endif
