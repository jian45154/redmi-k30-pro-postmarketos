#ifndef LMI_TEST_WAYLAND_CLIENT_H
#define LMI_TEST_WAYLAND_CLIENT_H

#include <stddef.h>
#include <stdint.h>

typedef int32_t wl_fixed_t;

struct wl_display;
struct wl_registry;
struct wl_compositor;
struct wl_shm;
struct wl_shm_pool;
struct wl_buffer;
struct wl_seat;
struct wl_pointer;
struct wl_touch;
struct wl_output;
struct wl_surface;

struct wl_interface {
	const char *name;
};

struct wl_array {
	size_t size;
	size_t alloc;
	void *data;
};

struct wl_buffer_listener {
	void (*release)(void *, struct wl_buffer *);
};

struct wl_pointer_listener {
	void (*enter)(void *, struct wl_pointer *, uint32_t, struct wl_surface *,
	              wl_fixed_t, wl_fixed_t);
	void (*leave)(void *, struct wl_pointer *, uint32_t, struct wl_surface *);
	void (*motion)(void *, struct wl_pointer *, uint32_t, wl_fixed_t, wl_fixed_t);
	void (*button)(void *, struct wl_pointer *, uint32_t, uint32_t, uint32_t,
	               uint32_t);
	void (*axis)(void *, struct wl_pointer *, uint32_t, uint32_t, wl_fixed_t);
	void (*frame)(void *, struct wl_pointer *);
	void (*axis_source)(void *, struct wl_pointer *, uint32_t);
	void (*axis_stop)(void *, struct wl_pointer *, uint32_t, uint32_t);
	void (*axis_discrete)(void *, struct wl_pointer *, uint32_t, int32_t);
};

struct wl_touch_listener {
	void (*down)(void *, struct wl_touch *, uint32_t, uint32_t,
	             struct wl_surface *, int32_t, wl_fixed_t, wl_fixed_t);
	void (*up)(void *, struct wl_touch *, uint32_t, uint32_t, int32_t);
	void (*motion)(void *, struct wl_touch *, uint32_t, int32_t,
	               wl_fixed_t, wl_fixed_t);
	void (*frame)(void *, struct wl_touch *);
	void (*cancel)(void *, struct wl_touch *);
};

struct wl_seat_listener {
	void (*capabilities)(void *, struct wl_seat *, uint32_t);
	void (*name)(void *, struct wl_seat *, const char *);
};

struct wl_output_listener {
	void (*geometry)(void *, struct wl_output *, int32_t, int32_t, int32_t,
	                 int32_t, int32_t, const char *, const char *, int32_t);
	void (*mode)(void *, struct wl_output *, uint32_t, int32_t, int32_t, int32_t);
	void (*done)(void *, struct wl_output *);
	void (*scale)(void *, struct wl_output *, int32_t);
	void (*name)(void *, struct wl_output *, const char *);
	void (*description)(void *, struct wl_output *, const char *);
};

struct wl_registry_listener {
	void (*global)(void *, struct wl_registry *, uint32_t, const char *, uint32_t);
	void (*global_remove)(void *, struct wl_registry *, uint32_t);
};

#define WL_SHM_FORMAT_ARGB8888 0
#define WL_KEYBOARD_KEY_STATE_RELEASED 0
#define WL_KEYBOARD_KEY_STATE_PRESSED 1
#define WL_POINTER_BUTTON_STATE_RELEASED 0
#define WL_SEAT_CAPABILITY_POINTER (UINT32_C(1) << 0)
#define WL_SEAT_CAPABILITY_TOUCH (UINT32_C(1) << 2)

extern const struct wl_interface wl_compositor_interface;
extern const struct wl_interface wl_shm_interface;
extern const struct wl_interface wl_seat_interface;
extern const struct wl_interface wl_output_interface;

double wl_fixed_to_double(wl_fixed_t);
struct wl_display *wl_display_connect(const char *);
struct wl_registry *wl_display_get_registry(struct wl_display *);
int wl_display_roundtrip(struct wl_display *);
int wl_display_get_fd(struct wl_display *);
int wl_display_prepare_read(struct wl_display *);
int wl_display_dispatch_pending(struct wl_display *);
int wl_display_flush(struct wl_display *);
void wl_display_cancel_read(struct wl_display *);
int wl_display_read_events(struct wl_display *);
int wl_registry_add_listener(struct wl_registry *,
	                     const struct wl_registry_listener *, void *);
void *wl_registry_bind(struct wl_registry *, uint32_t,
	               const struct wl_interface *, uint32_t);
struct wl_surface *wl_compositor_create_surface(struct wl_compositor *);
struct wl_shm_pool *wl_shm_create_pool(struct wl_shm *, int, int32_t);
struct wl_buffer *wl_shm_pool_create_buffer(
	struct wl_shm_pool *, int32_t, int32_t, int32_t, int32_t, uint32_t);
void wl_shm_pool_destroy(struct wl_shm_pool *);
int wl_buffer_add_listener(struct wl_buffer *,
	                   const struct wl_buffer_listener *, void *);
void wl_surface_attach(struct wl_surface *, struct wl_buffer *, int32_t, int32_t);
void wl_surface_damage_buffer(struct wl_surface *, int32_t, int32_t,
	                      int32_t, int32_t);
void wl_surface_commit(struct wl_surface *);
void wl_surface_set_buffer_scale(struct wl_surface *, int32_t);
struct wl_pointer *wl_seat_get_pointer(struct wl_seat *);
struct wl_touch *wl_seat_get_touch(struct wl_seat *);
int wl_pointer_add_listener(struct wl_pointer *,
	                    const struct wl_pointer_listener *, void *);
int wl_touch_add_listener(struct wl_touch *,
	                  const struct wl_touch_listener *, void *);
void wl_pointer_release(struct wl_pointer *);
void wl_touch_release(struct wl_touch *);
int wl_seat_add_listener(struct wl_seat *, const struct wl_seat_listener *, void *);
int wl_output_add_listener(struct wl_output *,
	                   const struct wl_output_listener *, void *);
void wl_array_init(struct wl_array *);
void *wl_array_add(struct wl_array *, size_t);
void wl_array_release(struct wl_array *);

#endif
