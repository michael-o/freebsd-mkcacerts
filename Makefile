# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2026 Michael Osipov <michaelo@FreeBSD.org>

PROG=		mkcacerts
SRCS=		main.c mkcacerts.c
MAN=		# TODO: mkcacerts.8 not written yet
BINDIR?=	${PREFIX}/sbin

LDADD=		-lssl -lcrypto

WARNS?=		6

.include <bsd.prog.mk>
