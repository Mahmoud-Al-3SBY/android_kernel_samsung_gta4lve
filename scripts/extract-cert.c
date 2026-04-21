/* Extract X.509 certificate in DER form from PKCS#11 or PEM.
 *
 * Copyright © 2014-2015 Red Hat, Inc. All Rights Reserved.
 * Copyright © 2015      Intel Corporation.
 *
 * Authors: David Howells <dhowells@redhat.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the licence, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/store.h>

#define PKEY_ID_PKCS7 2

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr,
		"Usage: scripts/extract-cert <source> <dest>\n");
	exit(2);
}

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_all(&file, &line, NULL, NULL, NULL))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static void drain_openssl_errors(void)
{
	const char *file;
	int line;

	if (ERR_peek_error() == 0)
		return;
	while (ERR_get_error_all(&file, &line, NULL, NULL, NULL)) {}
}

#define ERR(cond, fmt, ...)				\
	do {						\
		bool __cond = (cond);			\
		display_openssl_errors(__LINE__);	\
		if (__cond) {				\
			err(1, fmt, ## __VA_ARGS__);	\
		}					\
	} while(0)

static const char *key_pass;
static BIO *wb;
static char *cert_dst;
int kbuild_verbose;

static void write_cert(X509 *x509)
{
	char buf[200];

	if (!wb) {
		wb = BIO_new_file(cert_dst, "wb");
		ERR(!wb, "%s", cert_dst);
	}
	X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
	ERR(!i2d_X509_bio(wb, x509), "%s", cert_dst);
	if (kbuild_verbose)
		fprintf(stderr, "Extracted cert: %s\n", buf);
}

int main(int argc, char **argv)
{
	char *cert_src;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	kbuild_verbose = atoi(getenv("KBUILD_VERBOSE")?:"0");

        key_pass = getenv("KBUILD_SIGN_PIN");

	if (argc != 3)
		format();

	cert_src = argv[1];
	cert_dst = argv[2];

	if (!cert_src[0]) {
		FILE *f = fopen(cert_dst, "wb");
		ERR(!f, "%s", cert_dst);
		fclose(f);
		exit(0);
	} else if (!strncmp(cert_src, "pkcs11:", 7)) {
		OSSL_PROVIDER *pkcs11_provider;
		OSSL_STORE_CTX *store_ctx;
		OSSL_STORE_INFO *info;
		OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
		X509 *cert = NULL;

		pkcs11_provider = OSSL_PROVIDER_load(libctx, "pkcs11");
		ERR(!pkcs11_provider, "Load PKCS#11 provider");
		drain_openssl_errors();

		store_ctx = OSSL_STORE_open_ex(cert_src, libctx, NULL, NULL, NULL, NULL, NULL, NULL);
		ERR(!store_ctx, "Open PKCS#11 store");

		while (!OSSL_STORE_eof(store_ctx)) {
			info = OSSL_STORE_load(store_ctx);
			if (!info)
				continue;
			if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT) {
				cert = OSSL_STORE_INFO_get1_CERT(info);
				OSSL_STORE_INFO_free(info);
				break;
			}
			OSSL_STORE_INFO_free(info);
		}

		OSSL_STORE_close(store_ctx);
		ERR(!cert, "Get X.509 from PKCS#11");
		write_cert(cert);
		X509_free(cert);
		OSSL_PROVIDER_unload(pkcs11_provider);
		OSSL_LIB_CTX_free(libctx);
	} else {
		BIO *b;
		X509 *x509;

		b = BIO_new_file(cert_src, "rb");
		ERR(!b, "%s", cert_src);

		while (1) {
			x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
			if (wb && !x509) {
				unsigned long err = ERR_peek_last_error();
				if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
				    ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
					ERR_clear_error();
					break;
				}
			}
			ERR(!x509, "%s", cert_src);
			write_cert(x509);
		}
	}

	BIO_free(wb);

	return 0;
}

