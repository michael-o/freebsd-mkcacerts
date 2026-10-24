/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Michael Osipov <michaelo@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MKCACERTS_H
#define MKCACERTS_H

#define MKCACERTS_VERSION "0.1.0"

extern const char *mkcacerts_progname;

struct mkcacerts_opts {
	const char	*destdir;	/* -D, NULL if unset */
	const char	*distbase;	/* -d, NULL if unset */
	const char	*localbase;	/* -L, NULL if unset */
	int		 dryrun;	/* -n */
	int		 verbose;	/* -v */
};

/*
 * Resolves paths exactly like certctl(8), scans the trusted hashed
 * certificate directory, and (re)writes the Java PKCS#12 truststore.
 * Fatal errors are reported via err(3)/errx(3) and terminate the
 * process; this function only returns on success.
 */
void mkcacerts_run(const struct mkcacerts_opts *opts);

#endif /* !MKCACERTS_H */
