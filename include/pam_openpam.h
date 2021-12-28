/*
 * "pam_openpam.h"
 *
 * This file originally from https://github.com/KDE/kwallet-pam, with name "pam_darwin.h".
 *
 */

/*
    SPDX-FileCopyrightText: 2015 Samuel Gaist <samuel.gaist@edeltech.ch

    SPDX-License-Identifier: LGPL-2.1-or-later
*/

#ifndef PAM_DARWIN_H
#define PAM_DARWIN_H

#include <security/pam_modules.h>

void pam_vsyslog(const pam_handle_t *ph, int priority, const char *fmt, va_list args);
void pam_syslog(const pam_handle_t *ph, int priority, const char *fmt, ...);

#endif
