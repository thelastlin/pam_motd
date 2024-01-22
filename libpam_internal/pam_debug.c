/*
 * This provides the necessary functions to do debugging in PAM.
 * Cristian Gafton <gafton@redhat.com>
 */

#include "config.h"
#include <wchar.h>

#ifdef PAM_DEBUG

#include "_pam_macros.h"

#undef PAM_MACROS_H
#undef PAM_NO_HEADER_FUNCTIONS
#define PAM_DEBUG_C 1
#include "_pam_macros.h"

#else

extern int ISO_C_forbids_an_empty_translation_unit;

#endif /* PAM_DEBUG */
