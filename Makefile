# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2026 Michael Osipov <michaelo@FreeBSD.org>

PROG=		mkcacerts
SRCS=		main.c mkcacerts.c
MAN=		mkcacerts.8
BINDIR?=	${PREFIX}/sbin

LDADD=		-lssl -lcrypto

WARNS?=		6

.include <bsd.prog.mk>
