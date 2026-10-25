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
 *
 * mkcacerts(8) reads the trusted-certificate hashed directory maintained
 * by certctl(8) (see TRUSTED_PATH in usr.sbin/certctl/certctl.c) and
 * (re)generates a Java-compatible PKCS#12 truststore from it, so that a
 * JVM's default truststore can be derived from the system truststore
 * without ever invoking a JVM/keytool to build it.
 *
 * Path resolution (destdir/distbase/localbase, TRUSTDESTDIR/CERTDESTDIR
 * env vars) intentionally mirrors certctl(8) exactly, so that anyone who
 * already knows how to point certctl at a non-default location already
 * knows how to point mkcacerts at the matching one.
 */

#include <sys/types.h>
#include <sys/stat.h>
#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "mkcacerts.h"

#if !OPENSSL_VERSION_PREREQ(3, 0)
#error "OpenSSL 3.0 or later is required"
#endif

#define SSL_PATH		"/etc/ssl"
#define TRUSTED_DIR		"certs"
#define TRUSTED_PATH		SSL_PATH "/" TRUSTED_DIR
#define CACERTS_FILE		"cacerts"
#define CACERTS_PATH		SSL_PATH "/" CACERTS_FILE
#define OUTPUT_MODE		0444

const char *mkcacerts_progname = "mkcacerts";

struct cert_entry {
	X509	*x509;
	char	*name;		/* certctl(8) hashed file name, e.g.
				 * "deadbeef.0" -- initially; replaced with a
				 * derived PKCS#12 friendlyName before output
				 * (see assign_friendly_names) */
};

static void
vinfo(const char *fmt, va_list ap)
{
	fprintf(stderr, "%s: ", mkcacerts_progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

static void
mc_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vinfo(fmt, ap);
	va_end(ap);
}

static void
mc_verbose(const struct mkcacerts_opts *opts, const char *fmt, ...)
{
	va_list ap;

	if (!opts->verbose)
		return;
	va_start(ap, fmt);
	vinfo(fmt, ap);
	va_end(ap);
}

static char *
xstrdup(const char *s)
{
	char *r = strdup(s);

	if (r == NULL)
		err(1, "strdup");
	return (r);
}

static char *
xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *r;
	int n;

	va_start(ap, fmt);
	n = vasprintf(&r, fmt, ap);
	va_end(ap);
	if (n < 0)
		err(1, "vasprintf");
	return (r);
}

/*
 * Mirrors certctl(8)'s own destdir/distbase/localbase resolution
 * (set_defaults() in certctl.c): CLI flag wins, then the matching
 * environment variable, then a fallback.
 */
static char *
resolve_destdir(const struct mkcacerts_opts *opts)
{
	const char *v;

	if (opts->destdir != NULL)
		return (xstrdup(opts->destdir));
	if ((v = getenv("DESTDIR")) != NULL)
		return (xstrdup(v));
	return (xstrdup(""));
}

static char *
resolve_distbase(const struct mkcacerts_opts *opts)
{
	const char *v;

	if (opts->distbase != NULL)
		return (xstrdup(opts->distbase));
	if ((v = getenv("DISTBASE")) != NULL)
		return (xstrdup(v));
	return (xstrdup(""));
}

static char *
resolve_localbase(const struct mkcacerts_opts *opts)
{
	const char *v;
#if defined(__FreeBSD__)
	char buf[PATH_MAX];
	size_t len;
#endif

	if (opts->localbase != NULL)
		return (xstrdup(opts->localbase));
	if ((v = getenv("LOCALBASE")) != NULL)
		return (xstrdup(v));
#if defined(__FreeBSD__)
	len = sizeof(buf);
	if (sysctlbyname("user.localbase", buf, &len, NULL, 0) == 0) {
		buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
		return (xstrdup(buf));
	}
#endif
	return (xstrdup("/usr/local"));
}

/* Equivalent of certctl(8)'s expand_path() for non-%L templates. */
static char *
resolve_trusted_path(const char *destdir, const char *distbase)
{
	const char *v;

	if ((v = getenv("TRUSTDESTDIR")) != NULL)
		return (xstrdup(v));
	if ((v = getenv("CERTDESTDIR")) != NULL)
		return (xstrdup(v));
	return (xasprintf("%s%s%s", destdir, distbase, TRUSTED_PATH));
}

/* Equivalent of certctl(8)'s expand_path() for "%L..." templates. */
static char *
resolve_output_path(const char *destdir, const char *localbase)
{
	return (xasprintf("%s%s%s", destdir, localbase, CACERTS_PATH));
}

/*
 * Validates that a directory entry name matches certctl(8)'s hashed
 * filename convention: 8 lowercase hex digits, '.', then one or more
 * decimal digits (e.g. "deadbeef.0"). We never recompute the subject
 * hash ourselves -- the filename certctl already assigned is reused
 * verbatim, or as part of a derived name, as the PKCS#12 friendlyName
 * (see build_friendly_name()).
 */
static int
is_hashed_name(const char *name)
{
	size_t i;

	for (i = 0; i < 8; i++) {
		if (!isxdigit((unsigned char)name[i]))
			return (0);
		if (isalpha((unsigned char)name[i]) &&
		    isupper((unsigned char)name[i]))
			return (0);
	}
	if (name[8] != '.' || name[9] == '\0')
		return (0);
	for (i = 9; name[i] != '\0'; i++) {
		if (!isdigit((unsigned char)name[i]))
			return (0);
	}
	return (1);
}

static int
cmp_entry(const void *a, const void *b)
{
	const struct cert_entry *ea = a, *eb = b;

	return (X509_cmp(ea->x509, eb->x509));
}

/*
 * Scans trusted_path for certctl(8)-style hashed entries, following
 * symlinks. Dangling symlinks and unparseable files are skipped with a
 * warning (mirrors OpenSSL's own by_dir.c leniency toward a broken
 * hashed-dir entry); the overall scan only fails if nothing usable was
 * found at all.
 */
static struct cert_entry *
scan_trusted_dir(const struct mkcacerts_opts *opts, const char *trusted_path,
    size_t *out_n)
{
	DIR *d;
	struct dirent *de;
	struct cert_entry *entries = NULL;
	size_t n = 0, cap = 0;

	d = opendir(trusted_path);
	if (d == NULL)
		err(1, "%s", trusted_path);

	while ((de = readdir(d)) != NULL) {
		char *fullpath;
		struct stat st;
		FILE *fp;
		X509 *cert;

		if (!is_hashed_name(de->d_name))
			continue;

		fullpath = xasprintf("%s/%s", trusted_path, de->d_name);

		if (stat(fullpath, &st) != 0) {
			mc_warn("%s: %s, skipping", fullpath,
			    strerror(errno));
			free(fullpath);
			continue;
		}

		fp = fopen(fullpath, "r");
		if (fp == NULL) {
			mc_warn("%s: %s, skipping", fullpath,
			    strerror(errno));
			free(fullpath);
			continue;
		}

		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		fclose(fp);

		if (cert == NULL) {
			mc_warn("%s: unable to parse certificate, skipping",
			    fullpath);
			ERR_clear_error();
			free(fullpath);
			continue;
		}

		mc_verbose(opts, "found %s", de->d_name);

		if (n == cap) {
			cap = cap == 0 ? 64 : cap * 2;
			entries = realloc(entries,
			    cap * sizeof(*entries));
			if (entries == NULL)
				err(1, "realloc");
		}
		entries[n].x509 = cert;
		entries[n].name = xstrdup(de->d_name);
		n++;

		free(fullpath);
	}
	closedir(d);

	if (n == 0)
		errx(1, "%s: no usable certificates found", trusted_path);

	/* Sort like certctl(8)'s cert.pem bundle: by X509_cmp(), not by
	 * filename/hash -- see certcmp()/write_bundle() in certctl.c. */
	qsort(entries, n, sizeof(*entries), cmp_entry);

	for (size_t i = 1; i < n; i++) {
		if (X509_cmp(entries[i - 1].x509, entries[i].x509) == 0)
			mc_warn("duplicate certificate: %s and %s are "
			    "identical, including both", entries[i - 1].name,
			    entries[i].name);
	}

	*out_n = n;
	return (entries);
}

/*
 * Extracts the first NID attribute value from name, if any, transcoded
 * to UTF-8 regardless of its underlying ASN.1 string type. Returns
 * NULL (not an error) if name has no such attribute.
 */
static char *
extract_name_attr(X509_NAME *name, int nid)
{
	int idx;
	X509_NAME_ENTRY *entry;
	ASN1_STRING *data;
	unsigned char *utf8 = NULL;
	char *r;
	int len;

	idx = X509_NAME_get_index_by_NID(name, nid, -1);
	if (idx < 0)
		return (NULL);
	entry = X509_NAME_get_entry(name, idx);
	data = X509_NAME_ENTRY_get_data(entry);

	len = ASN1_STRING_to_UTF8(&utf8, data);
	if (len < 0)
		return (NULL);
	r = xasprintf("%.*s", len, (const char *)utf8);
	OPENSSL_free(utf8);
	return (r);
}

/*
 * Trims leading/trailing whitespace in place. The value is otherwise
 * used verbatim, in whatever case the certificate's subject stores it
 * -- OpenSSL has no Unicode-aware case folding, and byte-wise
 * lowercasing would corrupt any multi-byte UTF-8 character.
 */
static void
trim(char *s)
{
	size_t start, end;

	for (start = 0; isspace((unsigned char)s[start]); start++)
		continue;
	end = strlen(s);
	while (end > start && isspace((unsigned char)s[end - 1]))
		end--;

	size_t len = end - start;
	memmove(s, s + start, len);
	s[len] = '\0';
}

/*
 * Derives a human-readable friendlyName for cert: "<CN> (<hashed_name>)",
 * or "<OU> (<hashed_name>)" if there is no CN, or just <hashed_name>
 * verbatim if there is neither, or if the CN/OU found is empty or
 * entirely whitespace. hashed_name is the certctl(8)-assigned
 * <hash>.<N> file name this entry was found under, which is always
 * unique by construction, so appending it guarantees the result is
 * unique too -- without that, two certificates could derive the same
 * human-readable name and silently collide. It also means a
 * friendlyName can always be mapped back to the certctl(8) file it
 * came from.
 */
static char *
build_friendly_name(X509 *cert, const char *hashed_name)
{
	X509_NAME *subject = X509_get_subject_name(cert);
	char *base, *name;

	base = extract_name_attr(subject, NID_commonName);
	if (base == NULL)
		base = extract_name_attr(subject, NID_organizationalUnitName);
	if (base == NULL)
		return (xstrdup(hashed_name));

	trim(base);
	if (base[0] == '\0') {
		free(base);
		return (xstrdup(hashed_name));
	}
	name = xasprintf("%s (%s)", base, hashed_name);
	free(base);
	return (name);
}

/*
 * Replaces each entry's name with a friendlyName derived from its
 * certificate's subject (see build_friendly_name()).
 */
static void
assign_friendly_names(const struct mkcacerts_opts *opts,
    struct cert_entry *entries, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		char *friendly = build_friendly_name(entries[i].x509,
		    entries[i].name);

		free(entries[i].name);
		entries[i].name = friendly;

		mc_verbose(opts, "friendly name: %s", entries[i].name);
	}
}

#if OPENSSL_VERSION_PREREQ(3, 2)

static int
add_jdk_trust_attr(PKCS12_SAFEBAG *bag)
{
	STACK_OF(X509_ATTRIBUTE) *attrs;
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *usage_obj;

	usage_obj = OBJ_nid2obj(NID_anyExtendedKeyUsage);
	attr = X509_ATTRIBUTE_create(NID_oracle_jdk_trustedkeyusage,
	    V_ASN1_OBJECT, usage_obj);
	if (attr == NULL)
		return (0);

	/* get0_attrs() returns const; the openssl(1) pkcs12 command's own
	 * jdk_trust() callback casts it away the same way. Routed through
	 * uintptr_t since a direct cast trips -Wcast-qual. */
	attrs = (STACK_OF(X509_ATTRIBUTE) *)(uintptr_t)
	    PKCS12_SAFEBAG_get0_attrs(bag);
	if (X509at_add1_attr(&attrs, attr) == NULL) {
		X509_ATTRIBUTE_free(attr);
		return (0);
	}
	PKCS12_SAFEBAG_set0_attrs(bag, attrs);
	X509_ATTRIBUTE_free(attr);
	return (1);
}

#else /* OpenSSL 3.0/3.1: no NID_oracle_jdk_trustedkeyusage, no setter */

/* Oracle/Sun "trustedKeyUsage" PKCS#12 bag attribute OID - not registered
 * as a NID before OpenSSL 3.2, so it's passed as a dotted string. Once
 * the minimum supported OpenSSL is bumped to 3.2+, delete this whole
 * #else branch together with this comment. */
#define JDK_TRUSTEDKEYUSAGE_OID "2.16.840.1.113894.746875.1.1"

static int
add_jdk_trust_attr(PKCS12_SAFEBAG *bag)
{
	ASN1_OBJECT *usage_obj;

	usage_obj = OBJ_nid2obj(NID_anyExtendedKeyUsage);

	/* type = V_ASN1_OBJECT, len = -1 tells X509_ATTRIBUTE_set1_data to
	 * treat "bytes" as an ASN1_OBJECT* rather than a raw byte buffer. */
	return (PKCS12_add1_attr_by_txt(bag, JDK_TRUSTEDKEYUSAGE_OID,
	    V_ASN1_OBJECT, (const unsigned char *)usage_obj, -1));
}

#endif /* OPENSSL_VERSION_PREREQ(3, 2) */

static STACK_OF(PKCS12_SAFEBAG) *
build_cert_bags(struct cert_entry *entries, size_t n)
{
	STACK_OF(PKCS12_SAFEBAG) *bags;

	bags = sk_PKCS12_SAFEBAG_new_null();
	if (bags == NULL)
		err(1, "sk_PKCS12_SAFEBAG_new_null");

	for (size_t i = 0; i < n; i++) {
		PKCS12_SAFEBAG *bag;

		bag = PKCS12_SAFEBAG_create_cert(entries[i].x509);
		if (bag == NULL)
			errx(1, "PKCS12_SAFEBAG_create_cert failed for %s",
			    entries[i].name);

		if (!add_jdk_trust_attr(bag))
			errx(1, "failed to set JDK trust attribute for %s",
			    entries[i].name);

		if (!PKCS12_add_friendlyname_utf8(bag, entries[i].name,
		    (int)strlen(entries[i].name)))
			errx(1, "failed to set friendlyName for %s",
			    entries[i].name);

		if (!sk_PKCS12_SAFEBAG_push(bags, bag))
			err(1, "sk_PKCS12_SAFEBAG_push");
	}

	return (bags);
}

static PKCS12 *
build_pkcs12(struct cert_entry *entries, size_t n)
{
	STACK_OF(PKCS12_SAFEBAG) *bags;
	STACK_OF(PKCS7) *safes = NULL;
	PKCS12 *p12;

	bags = build_cert_bags(entries, n);

	/* nid_safe = -1 -> PKCS12_pack_p7data (UNENCRYPTED cert safe), the
	 * equivalent of openssl(1) pkcs12's "-certpbe NONE". Without this,
	 * JSSE's default javax.net.ssl.trustStorePassword="" load (which
	 * passes a NULL password, not an empty one) cannot decrypt the
	 * cert bags and silently loads zero trust anchors. */
	if (!PKCS12_add_safe_ex(&safes, bags, -1, 0, NULL, NULL, NULL))
		errx(1, "PKCS12_add_safe_ex failed");

	p12 = PKCS12_init(NID_pkcs7_data);
	if (p12 == NULL)
		errx(1, "PKCS12_init failed");

	if (!PKCS12_pack_authsafes(p12, safes))
		errx(1, "PKCS12_pack_authsafes failed");

	/* No MAC: this truststore is meant to be opened with no password
	 * at all, matching the vendor JDK cacerts files we've verified
	 * against. */

	sk_PKCS7_pop_free(safes, PKCS7_free);
	sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	return (p12);
}

static void
mkdirp_component(const char *path)
{
	struct stat st;

	/* Skip components that already exist (e.g. "/etc", "/usr/local")
	 * instead of relying on mkdir(2) returning EEXIST: on some systems
	 * a non-writable parent (e.g. "/") yields EACCES instead of EEXIST
	 * even though the target itself already exists. */
	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode))
			errx(1, "%s: not a directory", path);
		return;
	}
	if (mkdir(path, 0755) != 0 && errno != EEXIST)
		err(1, "%s", path);
}

static void
mkdirp(const char *path)
{
	char *copy, *p;

	copy = xstrdup(path);
	for (p = copy + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		mkdirp_component(copy);
		*p = '/';
	}
	mkdirp_component(copy);
	free(copy);
}

/*
 * Writes p12 to out_path atomically: a dot-prefixed temp file in the
 * same directory (mirrors certctl(8)'s write_certs()/write_bundle()
 * convention), fsync'd, chmod'd to OUTPUT_MODE, then renamed into
 * place -- so a JVM reading out_path concurrently never observes a
 * partially-written file, and a crash mid-write never corrupts the
 * previous good copy.
 */
static void
write_pkcs12_atomic(const struct mkcacerts_opts *opts, PKCS12 *p12,
    const char *out_path)
{
	char *out_dir, *out_base, *tmp_name;
	const char *slash;
	int dfd, fd;
	FILE *fp;

	slash = strrchr(out_path, '/');
	if (slash == NULL)
		errx(1, "%s: not an absolute path", out_path);
	out_dir = xasprintf("%.*s", (int)(slash - out_path), out_path);
	out_base = xstrdup(slash + 1);
	tmp_name = xasprintf(".%s", out_base);

	mkdirp(out_dir);

	if (opts->dryrun) {
		mc_verbose(opts, "dry-run: would write %s (%d bytes)",
		    out_path, i2d_PKCS12(p12, NULL));
		free(out_dir);
		free(out_base);
		free(tmp_name);
		return;
	}

	dfd = open(out_dir, O_DIRECTORY | O_RDONLY);
	if (dfd < 0)
		err(1, "%s", out_dir);

	fd = openat(dfd, tmp_name, O_CREAT | O_WRONLY | O_TRUNC,
	    OUTPUT_MODE);
	if (fd < 0)
		err(1, "%s/%s", out_dir, tmp_name);
	(void)fchmod(fd, OUTPUT_MODE);

	fp = fdopen(fd, "w");
	if (fp == NULL)
		err(1, "fdopen");

	if (!i2d_PKCS12_fp(fp, p12)) {
		unlinkat(dfd, tmp_name, 0);
		errx(1, "failed to write %s", out_path);
	}

	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
		unlinkat(dfd, tmp_name, 0);
		err(1, "%s/%s", out_dir, tmp_name);
	}
	fclose(fp);

	if (renameat(dfd, tmp_name, dfd, out_base) != 0) {
		int save_errno = errno;
		unlinkat(dfd, tmp_name, 0);
		errno = save_errno;
		err(1, "rename %s/%s to %s", out_dir, tmp_name, out_path);
	}

	close(dfd);
	free(out_dir);
	free(out_base);
	free(tmp_name);

	mc_verbose(opts, "wrote %s", out_path);
}

void
mkcacerts_run(const struct mkcacerts_opts *opts)
{
	char *destdir, *distbase, *localbase;
	char *trusted_path, *out_path;
	struct cert_entry *entries;
	size_t n;
	PKCS12 *p12;

	destdir = resolve_destdir(opts);
	distbase = resolve_distbase(opts);
	localbase = resolve_localbase(opts);
	trusted_path = resolve_trusted_path(destdir, distbase);
	out_path = resolve_output_path(destdir, localbase);

	mc_verbose(opts, "trusted directory: %s", trusted_path);
	mc_verbose(opts, "output path: %s", out_path);

	entries = scan_trusted_dir(opts, trusted_path, &n);
	mc_verbose(opts, "%zu certificate(s) found", n);

	assign_friendly_names(opts, entries, n);

	p12 = build_pkcs12(entries, n);
	write_pkcs12_atomic(opts, p12, out_path);

	PKCS12_free(p12);
	for (size_t i = 0; i < n; i++) {
		X509_free(entries[i].x509);
		free(entries[i].name);
	}
	free(entries);
	free(destdir);
	free(distbase);
	free(localbase);
	free(trusted_path);
	free(out_path);
}
