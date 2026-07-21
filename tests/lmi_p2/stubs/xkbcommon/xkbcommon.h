#ifndef LMI_TEST_XKBCOMMON_H
#define LMI_TEST_XKBCOMMON_H

#include <stdint.h>

typedef uint32_t xkb_keysym_t;

#define XKB_KEY_NoSymbol UINT32_C(0)
#define XKB_KEYSYM_CASE_INSENSITIVE 1

xkb_keysym_t xkb_keysym_from_name(const char *, int);
xkb_keysym_t xkb_utf32_to_keysym(uint32_t);

#endif
