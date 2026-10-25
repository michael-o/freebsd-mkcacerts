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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mkcacerts.h"

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-nv] [-D destdir] [-d distbase] [-L localbase]\n"
	    "       %s --version\n",
	    mkcacerts_progname, mkcacerts_progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	struct mkcacerts_opts opts;
	int ch;

	mkcacerts_progname = "mkcacerts";

	opts.destdir = NULL;
	opts.distbase = NULL;
	opts.localbase = NULL;
	opts.dryrun = 0;
	opts.verbose = 0;

	/*
	 * getopt(3) has no portable notion of long options, and --version
	 * must be recognized regardless of where it appears or what else
	 * is given. Scan for it by hand before getopt(3) ever runs, so
	 * neither its position nor its presence alongside short options
	 * matters.
	 */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--version") == 0) {
			printf("%s %s\n", mkcacerts_progname,
			    MKCACERTS_VERSION);
			return (0);
		}
	}

	while ((ch = getopt(argc, argv, "D:d:L:nv")) != -1) {
		switch (ch) {
		case 'D':
			opts.destdir = optarg;
			break;
		case 'd':
			opts.distbase = optarg;
			break;
		case 'L':
			opts.localbase = optarg;
			break;
		case 'n':
			opts.dryrun = 1;
			break;
		case 'v':
			opts.verbose = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	mkcacerts_run(&opts);
	return (0);
}
