#ifndef LMI_TEST_PANGOCAIRO_H
#define LMI_TEST_PANGOCAIRO_H

#include <cairo.h>

typedef struct PangoLayout PangoLayout;
typedef struct PangoFontDescription PangoFontDescription;

PangoLayout *pango_cairo_create_layout(cairo_t *);
PangoFontDescription *pango_font_description_from_string(const char *);
void pango_layout_set_font_description(PangoLayout *, const PangoFontDescription *);
void pango_layout_set_text(PangoLayout *, const char *, int);
void pango_layout_get_pixel_size(PangoLayout *, int *, int *);
void pango_cairo_show_layout(cairo_t *, PangoLayout *);
void pango_font_description_free(PangoFontDescription *);
void g_object_unref(void *);

#endif
