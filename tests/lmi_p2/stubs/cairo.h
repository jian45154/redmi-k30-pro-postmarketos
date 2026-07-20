#ifndef LMI_TEST_CAIRO_H
#define LMI_TEST_CAIRO_H

#include <stdint.h>

typedef struct cairo cairo_t;
typedef struct cairo_surface cairo_surface_t;
typedef int cairo_format_t;

#define CAIRO_FORMAT_ARGB32 0

cairo_surface_t *cairo_image_surface_create_for_data(
	unsigned char *, cairo_format_t, int, int, int);
cairo_t *cairo_create(cairo_surface_t *);
void cairo_set_source_rgb(cairo_t *, double, double, double);
void cairo_paint(cairo_t *);
void cairo_scale(cairo_t *, double, double);
void cairo_rectangle(cairo_t *, double, double, double, double);
void cairo_fill(cairo_t *);
void cairo_move_to(cairo_t *, double, double);
void cairo_destroy(cairo_t *);
void cairo_surface_flush(cairo_surface_t *);
void cairo_surface_destroy(cairo_surface_t *);

#endif
