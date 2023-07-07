/*
 * Copyright (c) 2001-2002 Andrew Morgan <morgan@kernel.org>
 *
 * <security/pam_modutil.h>
 *
 * This file is a list of handy libc wrappers that attempt to provide some
 * thread-safe and other convenient functionality to modules in a common form.
 *
 * A number of these functions reserve space in a pam_[sg]et_data item.
 * In all cases, the name of the item is prefixed with "pam_modutil_*".
 *
 * On systems that simply can't support thread safe programming, these
 * functions don't support it either - sorry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SECURITY__PAM_MODUTIL_H
#define _SECURITY__PAM_MODUTIL_H

#include <sys/types.h>
#include <security/pam_types.h>
#include <pwd.h>
#include <grp.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <security/pam_constants.h>

struct pam_modutil_privs {
	gid_t *grplist;
	int number_of_groups;
	int allocated;
	gid_t old_gid;
	uid_t old_uid;
	int is_dropped;
};

#define PAM_MODUTIL_NGROUPS     64
#define PAM_MODUTIL_DEF_PRIVS(n) \
	gid_t n##_grplist[PAM_MODUTIL_NGROUPS]; \
	struct pam_modutil_privs n = { n##_grplist, PAM_MODUTIL_NGROUPS, 0, -1, -1, 0 }

# define PAM_NONNULL(params)
extern int
pam_modutil_read(int fd, char *buffer, int count);

extern int PAM_NONNULL((1,2,3))
pam_modutil_drop_priv(pam_handle_t *pamh,
		      struct pam_modutil_privs *p,
		      const struct passwd *pw);

extern int PAM_NONNULL((1,2))
pam_modutil_regain_priv(pam_handle_t *pamh,
		      struct pam_modutil_privs *p);

enum pam_modutil_redirect_fd {
	PAM_MODUTIL_IGNORE_FD,	/* do not redirect */
	PAM_MODUTIL_PIPE_FD,	/* redirect to a pipe */
	PAM_MODUTIL_NULL_FD,	/* redirect to /dev/null */
};

extern struct passwd * PAM_NONNULL((1,2))
pam_modutil_getpwnam(pam_handle_t *pamh, const char *user);


/* redirect standard descriptors, close all other descriptors. */
extern int PAM_NONNULL((1))
pam_modutil_sanitize_helper_fds(pam_handle_t *pamh,
				enum pam_modutil_redirect_fd redirect_stdin,
				enum pam_modutil_redirect_fd redirect_stdout,
				enum pam_modutil_redirect_fd redirect_stderr);

/**************************************************
 * @brief Lookup a value for the key in the file (i.e. login.defs or a similar
 * key-value format file).
 *
 * @param[in] pamh The pam handle structure
 * @param[in] file_name Configuration file name
 * @param[in] key Lookup key
 *
 * @return value, or NULL if key was not found.
 **************************************************/
extern char * PAM_NONNULL((1,2,3))
pam_modutil_search_key(pam_handle_t *pamh,
		       const char *file_name,
		       const char *key);

#ifdef __cplusplus
}
#endif

#endif /* _SECURITY__PAM_MODUTIL_H */
