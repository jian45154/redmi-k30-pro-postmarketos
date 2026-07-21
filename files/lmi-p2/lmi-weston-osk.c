/*
 * SPDX-License-Identifier: MIT
 *
 * A small Weston input-method-v1 panel for native text-input clients in the
 * lmi P2 recovery UI.  Stock weston-terminal provides no compositor-authenticated
 * text-input focus, so terminal routing is deliberately absent.
 */

#define _GNU_SOURCE
#include <cairo.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input-event-codes.h>
#include <pango/pangocairo.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <xkbcommon/xkbcommon.h>

#include "input-method-unstable-v1-client-protocol.h"
#include "lmi-input-state.h"
#include "lmi-layer-state.h"

enum lmi_key_action {
	LMI_ACTION_TEXT,
	LMI_ACTION_KEYSYM,
	LMI_ACTION_LAYER,
	LMI_ACTION_MODIFIER,
};

#include "lmi-osk-layout.h"

enum {
	MOD_SHIFT = 1u << 0,
	MOD_CONTROL = 1u << 1,
	MOD_ALT = 1u << 2,
};

struct lmi_osk;
struct lmi_output;

struct lmi_buffer {
	struct lmi_osk *osk;
	struct wl_buffer *buffer;
	void *pixels;
	size_t size;
	bool busy;
};

struct lmi_output {
	struct lmi_osk *osk;
	struct wl_output *proxy;
	uint32_t global_name;
	char name[64];
	struct lmi_output *next;
};

struct lmi_osk {
	struct wl_display *display;
	struct wl_registry *registry;
	struct wl_compositor *compositor;
	struct wl_shm *shm;
	struct wl_seat *seat;
	struct wl_pointer *pointer;
	struct wl_touch *touch;
	struct lmi_output *outputs;
	struct lmi_output *selected_output;
	struct zwp_input_method_v1 *input_method;
	struct zwp_input_method_context_v1 *context;
	struct zwp_input_panel_v1 *input_panel;
	struct zwp_input_panel_surface_v1 *panel_surface;
	struct wl_surface *surface;
	struct lmi_buffer buffers[LMI_LAYER_COUNT];
	uint32_t serial;
	uint32_t modifiers;
	struct lmi_layer_state layer_state;
	double pointer_x;
	double pointer_y;
	int32_t touch_id;
	double touch_x;
	double touch_y;
	struct lmi_input_state input_state;
	bool output_ambiguous;
	bool setup_failed;
};

static uint32_t
monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (uint32_t)((uint64_t)now.tv_sec * 1000u +
	                  (uint64_t)now.tv_nsec / 1000000u);
}

static bool present_requested_layer(struct lmi_osk *osk);

static void
buffer_release(void *data, struct wl_buffer *wl_buffer)
{
	struct lmi_buffer *buffer = data;

	(void)wl_buffer;
	buffer->busy = false;
	if (lmi_layer_state_should_present(&buffer->osk->layer_state) &&
	    buffer == &buffer->osk->buffers[buffer->osk->layer_state.requested])
		(void)present_requested_layer(buffer->osk);
}

static const struct wl_buffer_listener buffer_listener = {
	buffer_release,
};

static int
create_anonymous_file(size_t size)
{
	const char *runtime = getenv("XDG_RUNTIME_DIR");
	char template[512];
	int fd;

	if (runtime == NULL || runtime[0] != '/' || strlen(runtime) > 400) {
		errno = EINVAL;
		return -1;
	}
	if (snprintf(template, sizeof(template), "%s/lmi-osk.XXXXXX", runtime) < 0) {
		errno = EINVAL;
		return -1;
	}
	fd = mkstemp(template);
	if (fd < 0)
		return -1;
	unlink(template);
	if (ftruncate(fd, (off_t)size) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void
draw_label(cairo_t *cairo, const char *label, double x, double y,
           double width, double height)
{
	PangoLayout *layout;
	PangoFontDescription *font;
	int text_width, text_height;

	layout = pango_cairo_create_layout(cairo);
	font = pango_font_description_from_string("DejaVu Sans 19");
	pango_layout_set_font_description(layout, font);
	pango_layout_set_text(layout, label, -1);
	pango_layout_get_pixel_size(layout, &text_width, &text_height);
	cairo_set_source_rgb(cairo, 0.96, 0.97, 0.98);
	cairo_move_to(cairo,
	              x + (width - (double)text_width) / 2.0,
	              y + (height - (double)text_height) / 2.0);
	pango_cairo_show_layout(cairo, layout);
	pango_font_description_free(font);
	g_object_unref(layout);
}

static void
render_layer(struct lmi_buffer *buffer, size_t layer_index)
{
	const struct lmi_layer *layer = &lmi_layers[layer_index];
	cairo_surface_t *image;
	cairo_t *cairo;
	size_t row_index;

	image = cairo_image_surface_create_for_data(
		buffer->pixels, CAIRO_FORMAT_ARGB32, LMI_BUFFER_WIDTH,
		LMI_BUFFER_HEIGHT, LMI_BUFFER_STRIDE);
	cairo = cairo_create(image);
	cairo_set_source_rgb(cairo, 0.055, 0.075, 0.10);
	cairo_paint(cairo);
	cairo_scale(cairo, LMI_OUTPUT_SCALE, LMI_OUTPUT_SCALE);

	for (row_index = 0; row_index < layer->row_count; row_index++) {
		const struct lmi_row *row = &layer->rows[row_index];
		double row_height =
			((double)LMI_LOGICAL_HEIGHT - 2.0 * LMI_MARGIN -
			 (double)(layer->row_count - 1) * LMI_GAP) /
			(double)layer->row_count;
		double y = LMI_MARGIN + row_index * (row_height + LMI_GAP);
		double drawable =
			(double)LMI_LOGICAL_WIDTH - 2.0 * LMI_MARGIN -
			(double)(row->key_count - 1) * LMI_GAP;
		uint32_t preceding_weight = 0;
		size_t key_index;

		for (key_index = 0; key_index < row->key_count; key_index++) {
			const struct lmi_key *key = &row->keys[key_index];
			double left = LMI_MARGIN + key_index * LMI_GAP +
			              drawable * preceding_weight / row->total_weight;
			double right;
			double key_width;

			preceding_weight += key->weight;
			right = LMI_MARGIN + key_index * LMI_GAP +
			        drawable * preceding_weight / row->total_weight;
			key_width = right - left;
			if (key->action == LMI_ACTION_LAYER ||
			    key->action == LMI_ACTION_MODIFIER)
				cairo_set_source_rgb(cairo, 0.18, 0.31, 0.44);
			else
				cairo_set_source_rgb(cairo, 0.16, 0.18, 0.22);
			cairo_rectangle(cairo, left, y, key_width, row_height);
			cairo_fill(cairo);
			draw_label(cairo, key->label, left, y, key_width, row_height);
		}
	}

	cairo_destroy(cairo);
	cairo_surface_flush(image);
	cairo_surface_destroy(image);
}

static int
create_buffer(struct lmi_osk *osk, size_t layer_index)
{
	struct lmi_buffer *buffer = &osk->buffers[layer_index];
	struct wl_shm_pool *pool;
	int fd;

	buffer->osk = osk;
	buffer->size = (size_t)LMI_BUFFER_STRIDE * LMI_BUFFER_HEIGHT;
	fd = create_anonymous_file(buffer->size);
	if (fd < 0)
		return -1;
	buffer->pixels = mmap(NULL, buffer->size, PROT_READ | PROT_WRITE,
	                      MAP_SHARED, fd, 0);
	if (buffer->pixels == MAP_FAILED) {
		close(fd);
		return -1;
	}
	pool = wl_shm_create_pool(osk->shm, fd, (int32_t)buffer->size);
	close(fd);
	if (pool == NULL) {
		munmap(buffer->pixels, buffer->size);
		buffer->pixels = NULL;
		return -1;
	}
	buffer->buffer = wl_shm_pool_create_buffer(
		pool, 0, LMI_BUFFER_WIDTH, LMI_BUFFER_HEIGHT,
		LMI_BUFFER_STRIDE, WL_SHM_FORMAT_ARGB8888);
	wl_shm_pool_destroy(pool);
	if (buffer->buffer == NULL) {
		munmap(buffer->pixels, buffer->size);
		buffer->pixels = NULL;
		return -1;
	}
	wl_buffer_add_listener(buffer->buffer, &buffer_listener, buffer);
	render_layer(buffer, layer_index);
	return 0;
}

static bool
present_requested_layer(struct lmi_osk *osk)
{
	struct lmi_buffer *buffer = &osk->buffers[osk->layer_state.requested];

	if (!lmi_layer_state_should_present(&osk->layer_state) ||
	    osk->surface == NULL || buffer->buffer == NULL || buffer->busy)
		return false;
	wl_surface_attach(osk->surface, buffer->buffer, 0, 0);
	wl_surface_damage_buffer(osk->surface, 0, 0,
	                         LMI_BUFFER_WIDTH, LMI_BUFFER_HEIGHT);
	wl_surface_commit(osk->surface);
	buffer->busy = true;
	lmi_layer_state_mark_presented(&osk->layer_state);
	return true;
}

static void
request_layer(struct lmi_osk *osk, size_t layer_index)
{
	lmi_layer_state_request(&osk->layer_state, layer_index);
	(void)present_requested_layer(osk);
}

static const struct lmi_key *
key_at(struct lmi_osk *osk, double x, double y)
{
	const struct lmi_layer *layer = &lmi_layers[osk->layer_state.displayed];
	double row_height;
	size_t row_index, key_index;
	const struct lmi_row *row;
	double drawable;
	uint32_t preceding_weight = 0;

	if (x < LMI_MARGIN || x >= LMI_LOGICAL_WIDTH - LMI_MARGIN ||
	    y < LMI_MARGIN || y >= LMI_LOGICAL_HEIGHT - LMI_MARGIN)
		return NULL;
	row_height = ((double)LMI_LOGICAL_HEIGHT - 2.0 * LMI_MARGIN -
	              (double)(layer->row_count - 1) * LMI_GAP) /
	             (double)layer->row_count;
	row_index = (size_t)((y - LMI_MARGIN) / (row_height + LMI_GAP));
	if (row_index >= layer->row_count)
		return NULL;
	if (y >= LMI_MARGIN + row_index * (row_height + LMI_GAP) + row_height)
		return NULL;
	row = &layer->rows[row_index];
	drawable = (double)LMI_LOGICAL_WIDTH - 2.0 * LMI_MARGIN -
	           (double)(row->key_count - 1) * LMI_GAP;
	for (key_index = 0; key_index < row->key_count; key_index++) {
		const struct lmi_key *key = &row->keys[key_index];
		double left = LMI_MARGIN + key_index * LMI_GAP +
		              drawable * preceding_weight / row->total_weight;
		double right;

		preceding_weight += key->weight;
		right = LMI_MARGIN + key_index * LMI_GAP +
		        drawable * preceding_weight / row->total_weight;
		if (x >= left && x < right)
			return key;
	}
	return NULL;
}

static void
send_keysym(struct lmi_osk *osk, xkb_keysym_t symbol)
{
	uint32_t time;

	if (osk->context == NULL || symbol == XKB_KEY_NoSymbol)
		return;
	time = monotonic_milliseconds();
	zwp_input_method_context_v1_keysym(
		osk->context, osk->serial, time, symbol,
		WL_KEYBOARD_KEY_STATE_PRESSED, osk->modifiers);
	zwp_input_method_context_v1_keysym(
		osk->context, osk->serial, time, symbol,
		WL_KEYBOARD_KEY_STATE_RELEASED, osk->modifiers);
}

static void
activate_key(struct lmi_osk *osk, const struct lmi_key *key)
{
	xkb_keysym_t symbol;
	size_t index;

	if (key == NULL)
		return;
	switch (key->action) {
	case LMI_ACTION_LAYER:
		for (index = 0; index < LMI_LAYER_COUNT; index++) {
			if (strcmp(lmi_layers[index].name, key->value) == 0) {
				request_layer(osk, index);
				return;
			}
		}
		return;
	case LMI_ACTION_MODIFIER:
		if (strcmp(key->value, "shift") == 0)
			osk->modifiers ^= MOD_SHIFT;
		else if (strcmp(key->value, "control") == 0)
			osk->modifiers ^= MOD_CONTROL;
		else if (strcmp(key->value, "alt") == 0)
			osk->modifiers ^= MOD_ALT;
		return;
	case LMI_ACTION_KEYSYM:
		if (osk->input_state.route == LMI_INPUT_EDITOR &&
		           osk->context != NULL) {
			symbol = xkb_keysym_from_name(
				key->value, XKB_KEYSYM_CASE_INSENSITIVE);
			send_keysym(osk, symbol);
		}
		break;
	case LMI_ACTION_TEXT:
		if (osk->input_state.route == LMI_INPUT_EDITOR &&
		           osk->context != NULL && osk->modifiers == 0) {
			zwp_input_method_context_v1_commit_string(
				osk->context, osk->serial, key->value);
		} else if (osk->input_state.route == LMI_INPUT_EDITOR &&
		           osk->context != NULL && key->value[0] != '\0' &&
		           key->value[1] == '\0') {
			symbol = xkb_utf32_to_keysym((uint8_t)key->value[0]);
			send_keysym(osk, symbol);
		}
		break;
	}
	osk->modifiers = 0;
	if (strcmp(lmi_layers[osk->layer_state.displayed].name, "upper") == 0) {
		for (index = 0; index < LMI_LAYER_COUNT; index++) {
			if (strcmp(lmi_layers[index].name, "lower") == 0) {
				request_layer(osk, index);
				break;
			}
		}
	}
}

static void
pointer_enter(void *data, struct wl_pointer *pointer, uint32_t serial,
	      struct wl_surface *surface, wl_fixed_t x, wl_fixed_t y)
{
	struct lmi_osk *osk = data;
	(void)pointer;
	(void)serial;
	(void)surface;
	osk->pointer_x = wl_fixed_to_double(x);
	osk->pointer_y = wl_fixed_to_double(y);
}

static void
pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
	      struct wl_surface *surface)
{
	(void)data;
	(void)pointer;
	(void)serial;
	(void)surface;
}

static void
pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
	       wl_fixed_t x, wl_fixed_t y)
{
	struct lmi_osk *osk = data;
	(void)pointer;
	(void)time;
	osk->pointer_x = wl_fixed_to_double(x);
	osk->pointer_y = wl_fixed_to_double(y);
}

static void
pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
	       uint32_t time, uint32_t button, uint32_t state)
{
	struct lmi_osk *osk = data;
	(void)pointer;
	(void)serial;
	(void)time;
	if (button == BTN_LEFT && state == WL_POINTER_BUTTON_STATE_RELEASED)
		activate_key(osk, key_at(osk, osk->pointer_x, osk->pointer_y));
}

static void
pointer_axis(void *data, struct wl_pointer *pointer, uint32_t time,
	     uint32_t axis, wl_fixed_t value)
{
	(void)data;
	(void)pointer;
	(void)time;
	(void)axis;
	(void)value;
}

static void
pointer_frame(void *data, struct wl_pointer *pointer)
{
	(void)data;
	(void)pointer;
}

static void
pointer_axis_source(void *data, struct wl_pointer *pointer, uint32_t source)
{
	(void)data;
	(void)pointer;
	(void)source;
}

static void
pointer_axis_stop(void *data, struct wl_pointer *pointer, uint32_t time,
	          uint32_t axis)
{
	(void)data;
	(void)pointer;
	(void)time;
	(void)axis;
}

static void
pointer_axis_discrete(void *data, struct wl_pointer *pointer, uint32_t axis,
	              int32_t discrete)
{
	(void)data;
	(void)pointer;
	(void)axis;
	(void)discrete;
}

static const struct wl_pointer_listener pointer_listener = {
	.enter = pointer_enter,
	.leave = pointer_leave,
	.motion = pointer_motion,
	.button = pointer_button,
	.axis = pointer_axis,
	.frame = pointer_frame,
	.axis_source = pointer_axis_source,
	.axis_stop = pointer_axis_stop,
	.axis_discrete = pointer_axis_discrete,
};

static void
touch_down(void *data, struct wl_touch *touch, uint32_t serial, uint32_t time,
	   struct wl_surface *surface, int32_t id, wl_fixed_t x, wl_fixed_t y)
{
	struct lmi_osk *osk = data;
	(void)touch;
	(void)serial;
	(void)time;
	(void)surface;
	if (osk->touch_id == -1) {
		osk->touch_id = id;
		osk->touch_x = wl_fixed_to_double(x);
		osk->touch_y = wl_fixed_to_double(y);
	}
}

static void
touch_up(void *data, struct wl_touch *touch, uint32_t serial,
	 uint32_t time, int32_t id)
{
	struct lmi_osk *osk = data;
	(void)touch;
	(void)serial;
	(void)time;
	if (id == osk->touch_id) {
		activate_key(osk, key_at(osk, osk->touch_x, osk->touch_y));
		osk->touch_id = -1;
	}
}

static void
touch_motion(void *data, struct wl_touch *touch, uint32_t time, int32_t id,
	     wl_fixed_t x, wl_fixed_t y)
{
	struct lmi_osk *osk = data;
	(void)touch;
	(void)time;
	if (id == osk->touch_id) {
		osk->touch_x = wl_fixed_to_double(x);
		osk->touch_y = wl_fixed_to_double(y);
	}
}

static void touch_frame(void *data, struct wl_touch *touch)
{
	(void)data;
	(void)touch;
}

static void touch_cancel(void *data, struct wl_touch *touch)
{
	struct lmi_osk *osk = data;
	(void)touch;
	osk->touch_id = -1;
}

static const struct wl_touch_listener touch_listener = {
	.down = touch_down,
	.up = touch_up,
	.motion = touch_motion,
	.frame = touch_frame,
	.cancel = touch_cancel,
};

static void
seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities)
{
	struct lmi_osk *osk = data;

	if (!(capabilities & WL_SEAT_CAPABILITY_POINTER) && osk->pointer != NULL) {
		wl_pointer_release(osk->pointer);
		osk->pointer = NULL;
	}
	if (!(capabilities & WL_SEAT_CAPABILITY_TOUCH) && osk->touch != NULL) {
		wl_touch_release(osk->touch);
		osk->touch = NULL;
		osk->touch_id = -1;
	}
	if ((capabilities & WL_SEAT_CAPABILITY_POINTER) && osk->pointer == NULL) {
		osk->pointer = wl_seat_get_pointer(seat);
		wl_pointer_add_listener(osk->pointer, &pointer_listener, osk);
	}
	if ((capabilities & WL_SEAT_CAPABILITY_TOUCH) && osk->touch == NULL) {
		osk->touch = wl_seat_get_touch(seat);
		wl_touch_add_listener(osk->touch, &touch_listener, osk);
	}
}

static void
seat_name(void *data, struct wl_seat *seat, const char *name)
{
	(void)data;
	(void)seat;
	(void)name;
}

static const struct wl_seat_listener seat_listener = {
	.capabilities = seat_capabilities,
	.name = seat_name,
};

static void context_surrounding_text(void *data,
	struct zwp_input_method_context_v1 *context, const char *text,
	uint32_t cursor, uint32_t anchor)
{
	(void)data; (void)context; (void)text; (void)cursor; (void)anchor;
}

static void context_reset(void *data,
	struct zwp_input_method_context_v1 *context)
{
	(void)data; (void)context;
}

static void context_content_type(void *data,
	struct zwp_input_method_context_v1 *context, uint32_t hint,
	uint32_t purpose)
{
	(void)data; (void)context; (void)hint; (void)purpose;
}

static void context_invoke_action(void *data,
	struct zwp_input_method_context_v1 *context, uint32_t button,
	uint32_t index)
{
	(void)data; (void)context; (void)button; (void)index;
}

static void context_commit_state(void *data,
	struct zwp_input_method_context_v1 *context, uint32_t serial)
{
	struct lmi_osk *osk = data;
	(void)context;
	osk->serial = serial;
}

static void context_preferred_language(void *data,
	struct zwp_input_method_context_v1 *context, const char *language)
{
	(void)data; (void)context; (void)language;
}

static const struct zwp_input_method_context_v1_listener context_listener = {
	context_surrounding_text,
	context_reset,
	context_content_type,
	context_invoke_action,
	context_commit_state,
	context_preferred_language,
};

static void
send_modifier_map(struct zwp_input_method_context_v1 *context)
{
	static const char names[] = "Shift\0Control\0Mod1\0";
	struct wl_array map;
	void *destination;

	wl_array_init(&map);
	destination = wl_array_add(&map, sizeof(names));
	if (destination != NULL) {
		memcpy(destination, names, sizeof(names));
		zwp_input_method_context_v1_modifiers_map(context, &map);
	}
	wl_array_release(&map);
}

static void
input_method_activate(void *data, struct zwp_input_method_v1 *input_method,
	struct zwp_input_method_context_v1 *context)
{
	struct lmi_osk *osk = data;
	(void)input_method;
	if (osk->context != NULL)
		zwp_input_method_context_v1_destroy(osk->context);
	osk->context = context;
	osk->serial = 0;
	lmi_input_state_context_activated(&osk->input_state);
	zwp_input_method_context_v1_add_listener(context, &context_listener, osk);
	if (osk->input_state.route == LMI_INPUT_EDITOR)
		send_modifier_map(context);
	(void)present_requested_layer(osk);
}

static void
input_method_deactivate(void *data, struct zwp_input_method_v1 *input_method,
	struct zwp_input_method_context_v1 *context)
{
	struct lmi_osk *osk = data;
	(void)input_method;
	if (osk->context == context) {
		zwp_input_method_context_v1_destroy(context);
		osk->context = NULL;
		lmi_input_state_context_deactivated(&osk->input_state);
		osk->modifiers = 0;
	}
}

static const struct zwp_input_method_v1_listener input_method_listener = {
	.activate = input_method_activate,
	.deactivate = input_method_deactivate,
};

static uint32_t min_version(uint32_t advertised, uint32_t wanted)
{
	return advertised < wanted ? advertised : wanted;
}

static void
output_geometry(void *data, struct wl_output *output, int32_t x, int32_t y,
	        int32_t physical_width, int32_t physical_height, int32_t subpixel,
	        const char *make, const char *model, int32_t transform)
{
	(void)data; (void)output; (void)x; (void)y; (void)physical_width;
	(void)physical_height; (void)subpixel; (void)make; (void)model;
	(void)transform;
}

static void
output_mode(void *data, struct wl_output *output, uint32_t flags,
	    int32_t width, int32_t height, int32_t refresh)
{
	(void)data; (void)output; (void)flags; (void)width; (void)height;
	(void)refresh;
}

static void
output_done(void *data, struct wl_output *output)
{
	(void)data;
	(void)output;
}

static void
output_scale(void *data, struct wl_output *output, int32_t factor)
{
	(void)data;
	(void)output;
	(void)factor;
}

static void
output_name(void *data, struct wl_output *output, const char *name)
{
	struct lmi_output *candidate = data;
	struct lmi_osk *osk = candidate->osk;
	int length;

	(void)output;
	length = snprintf(candidate->name, sizeof(candidate->name), "%s", name);
	if (length < 0 || (size_t)length >= sizeof(candidate->name)) {
		osk->setup_failed = true;
		return;
	}
	if (strcmp(candidate->name, LMI_OUTPUT_CONNECTOR) != 0)
		return;
	if (osk->selected_output != NULL && osk->selected_output != candidate) {
		osk->selected_output = NULL;
		osk->output_ambiguous = true;
		return;
	}
	if (!osk->output_ambiguous)
		osk->selected_output = candidate;
}

static void
output_description(void *data, struct wl_output *output, const char *description)
{
	(void)data;
	(void)output;
	(void)description;
}

static const struct wl_output_listener output_listener = {
	.geometry = output_geometry,
	.mode = output_mode,
	.done = output_done,
	.scale = output_scale,
	.name = output_name,
	.description = output_description,
};

static void
registry_global(void *data, struct wl_registry *registry, uint32_t name,
	const char *interface, uint32_t version)
{
	struct lmi_osk *osk = data;

	if (strcmp(interface, wl_compositor_interface.name) == 0) {
		osk->compositor = wl_registry_bind(
			registry, name, &wl_compositor_interface, min_version(version, 4));
	} else if (strcmp(interface, wl_shm_interface.name) == 0) {
		osk->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
	} else if (strcmp(interface, wl_seat_interface.name) == 0 &&
	           osk->seat == NULL && version >= 5) {
		osk->seat = wl_registry_bind(
			registry, name, &wl_seat_interface, min_version(version, 5));
		wl_seat_add_listener(osk->seat, &seat_listener, osk);
	} else if (strcmp(interface, wl_output_interface.name) == 0 && version >= 4) {
		struct lmi_output *output = calloc(1, sizeof(*output));

		if (output == NULL) {
			osk->setup_failed = true;
			return;
		}
		output->osk = osk;
		output->global_name = name;
		output->proxy = wl_registry_bind(
			registry, name, &wl_output_interface, 4);
		if (output->proxy == NULL) {
			free(output);
			osk->setup_failed = true;
			return;
		}
		output->next = osk->outputs;
		osk->outputs = output;
		wl_output_add_listener(output->proxy, &output_listener, output);
	} else if (strcmp(interface, zwp_input_method_v1_interface.name) == 0) {
		osk->input_method = wl_registry_bind(
			registry, name, &zwp_input_method_v1_interface, 1);
		zwp_input_method_v1_add_listener(
			osk->input_method, &input_method_listener, osk);
	} else if (strcmp(interface, zwp_input_panel_v1_interface.name) == 0) {
		osk->input_panel = wl_registry_bind(
			registry, name, &zwp_input_panel_v1_interface, 1);
	}
}

static void
registry_remove(void *data, struct wl_registry *registry, uint32_t name)
{
	struct lmi_osk *osk = data;
	struct lmi_output *output;

	(void)registry;
	for (output = osk->outputs; output != NULL; output = output->next) {
		if (output->global_name == name) {
			if (osk->selected_output == output)
				osk->selected_output = NULL;
			break;
		}
	}
}

static const struct wl_registry_listener registry_listener = {
	registry_global,
	registry_remove,
};

static int
create_panel(struct lmi_osk *osk)
{
	size_t index;

	if (osk->setup_failed || osk->output_ambiguous ||
	    osk->compositor == NULL || osk->shm == NULL ||
	    osk->selected_output == NULL ||
	    osk->input_method == NULL || osk->input_panel == NULL ||
	    osk->seat == NULL)
		return -1;
	for (index = 0; index < LMI_LAYER_COUNT; index++) {
		if (create_buffer(osk, index) < 0)
			return -1;
	}
	osk->surface = wl_compositor_create_surface(osk->compositor);
	if (osk->surface == NULL)
		return -1;
	wl_surface_set_buffer_scale(osk->surface, LMI_OUTPUT_SCALE);
	osk->panel_surface = zwp_input_panel_v1_get_input_panel_surface(
		osk->input_panel, osk->surface);
	if (osk->panel_surface == NULL)
		return -1;
	zwp_input_panel_surface_v1_set_toplevel(
		osk->panel_surface, osk->selected_output->proxy,
		ZWP_INPUT_PANEL_SURFACE_V1_POSITION_CENTER_BOTTOM);
	(void)present_requested_layer(osk);
	return 0;
}

static int
dispatch_loop(struct lmi_osk *osk)
{
	int display_fd = wl_display_get_fd(osk->display);

	for (;;) {
		struct pollfd descriptor = { .fd = display_fd, .events = POLLIN };
		int changed;
		int flushed;

		while (wl_display_prepare_read(osk->display) != 0) {
			if (wl_display_dispatch_pending(osk->display) < 0)
				return -1;
		}
		flushed = wl_display_flush(osk->display);
		if (flushed < 0) {
			if (errno != EAGAIN) {
				wl_display_cancel_read(osk->display);
				return -1;
			}
			descriptor.events |= POLLOUT;
		}
		changed = poll(&descriptor, 1, -1);
		if (changed < 0) {
			wl_display_cancel_read(osk->display);
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (descriptor.revents & POLLIN) {
			if (wl_display_read_events(osk->display) < 0)
				return -1;
		} else {
			wl_display_cancel_read(osk->display);
		}
		if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			errno = EPIPE;
			return -1;
		}
		if (descriptor.revents & POLLOUT) {
			if (wl_display_flush(osk->display) < 0 && errno != EAGAIN)
				return -1;
		}
		if (wl_display_dispatch_pending(osk->display) < 0)
			return -1;
	}
}

int
main(int argc, char **argv)
{
	struct lmi_osk osk;

	(void)argv;
	if (argc != 1 || getuid() == 0 || geteuid() == 0) {
		fprintf(stderr, "lmi-weston-osk requires one unprivileged session\n");
		return 64;
	}
	memset(&osk, 0, sizeof(osk));
	lmi_input_state_init(&osk.input_state);
	lmi_layer_state_init(&osk.layer_state);
	osk.touch_id = -1;
	osk.display = wl_display_connect(NULL);
	if (osk.display == NULL) {
		fprintf(stderr, "could not connect to the Weston display\n");
		return 1;
	}
	osk.registry = wl_display_get_registry(osk.display);
	wl_registry_add_listener(osk.registry, &registry_listener, &osk);
	if (wl_display_roundtrip(osk.display) < 0 ||
	    wl_display_roundtrip(osk.display) < 0 || create_panel(&osk) < 0) {
		fprintf(stderr,
		        "required Weston globals or exact DSI-1 output are unavailable\n");
		return 1;
	}
	if (dispatch_loop(&osk) < 0)
		fprintf(stderr, "Weston display dispatch failed\n");
	return 1;
}
