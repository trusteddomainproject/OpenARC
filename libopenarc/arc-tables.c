/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, 2014-2016, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <string.h>
#include <assert.h>

/* libopenarc includes */
#include "arc-tables.h"
#include "arc-internal.h"

/* lookup tables */
static struct nametable prv_algorithms[] =	/* signing algorithms */
{
	{ "rsa-sha1",	ARC_SIGN_RSASHA1 },
	{ "rsa-sha256",	ARC_SIGN_RSASHA256 },
	{ NULL,		-1 },
};
struct nametable *algorithms = prv_algorithms;

static struct nametable prv_archdrnames[] =	/* header field names:types */
{
	{ ARC_AR_HDRNAME,	ARC_KVSETTYPE_AR },
	{ ARC_SEAL_HDRNAME,	ARC_KVSETTYPE_SEAL },
	{ ARC_MSGSIG_HDRNAME,	ARC_KVSETTYPE_SIGNATURE },
	{ NULL,			-1 },
};
struct nametable *archdrnames = prv_archdrnames;

static struct nametable prv_canonicalizations[] = /* canonicalizations */
{
	{ "simple",	ARC_CANON_SIMPLE },
	{ "relaxed",	ARC_CANON_RELAXED },
	{ NULL,		-1 },
};
struct nametable *canonicalizations = prv_canonicalizations;

static struct nametable prv_hashes[] =		/* hashes */
{
	{ "sha1",	ARC_HASHTYPE_SHA1 },
	{ "sha256",	ARC_HASHTYPE_SHA256 },
	{ NULL,		-1 },
};
struct nametable *hashes = prv_hashes;

static struct nametable prv_keyflags[] =	/* key flags */
{
	{ "y",		ARC_KEYFLAG_TESTKEY },
	{ "s",		ARC_KEYFLAG_NOSUBDOMAIN },
	{ NULL,		-1 }
};
struct nametable *keyflags = prv_keyflags;

static struct nametable prv_keytypes[] =	/* key types */
{
	{ "rsa",	ARC_KEYTYPE_RSA },
	{ NULL,		-1 },
};
struct nametable *keytypes = prv_keytypes;

static struct nametable prv_querytypes[] =	/* query types */
{
	{ "dns",	ARC_QUERY_DNS },
	{ NULL,		-1 },
};
struct nametable *querytypes = prv_querytypes;

static struct nametable prv_chainstatus[] =	/* chain status */
{
	{ "none",	ARC_CHAIN_NONE },
	{ "fail",	ARC_CHAIN_FAIL },
	{ "pass",	ARC_CHAIN_PASS },
	{ "unknown",	ARC_CHAIN_UNKNOWN },
	{ NULL,		-1 },
};
struct nametable *chainstatus = prv_chainstatus;

static struct nametable prv_results[] =		/* result codes */
{
	{ "Success",			ARC_STAT_OK },
	{ "Bad signature",		ARC_STAT_BADSIG },
	{ "No signature",		ARC_STAT_NOSIG },
	{ "No key",			ARC_STAT_NOKEY },
	{ "Unable to verify",		ARC_STAT_CANTVRFY },
	{ "Syntax error",		ARC_STAT_SYNTAX },
	{ "Resource unavailable",	ARC_STAT_NORESOURCE },
	{ "Internal error",		ARC_STAT_INTERNAL },
	{ "Revoked key",		ARC_STAT_REVOKED },
	{ "Invalid parameter",		ARC_STAT_INVALID },
	{ "Not implemented",		ARC_STAT_NOTIMPLEMENT },
	{ "Key retrieval failed",	ARC_STAT_KEYFAIL },
	{ NULL,				-1 },
};
struct nametable *results = prv_results;

static struct nametable prv_settypes[] =	/* set types */
{
	{ "key",			ARC_KVSETTYPE_KEY },
	{ "ARC signature",		ARC_KVSETTYPE_SIGNATURE },
	{ "ARC seal", 			ARC_KVSETTYPE_SEAL },
	{ "ARC results", 		ARC_KVSETTYPE_AR },
	{ NULL,				-1 },
};
struct nametable *settypes = prv_settypes;

static struct nametable prv_sigerrors[] =	/* signature parsing errors */
{
	{ "no signature error", 		ARC_SIGERROR_OK },
	{ "unsupported signature version",	ARC_SIGERROR_VERSION },
	{ "invalid domain coverage",		ARC_SIGERROR_DOMAIN },
	{ "signature expired",			ARC_SIGERROR_EXPIRED },
	{ "signature timestamp in the future",	ARC_SIGERROR_FUTURE },
	{ "signature timestamp order error",	ARC_SIGERROR_TIMESTAMPS },
	{ "invalid header canonicalization",	ARC_SIGERROR_INVALID_HC },
	{ "invalid body canonicalization",	ARC_SIGERROR_INVALID_BC },
	{ "signature algorithm missing",	ARC_SIGERROR_MISSING_A },
	{ "signature algorithm invalid",	ARC_SIGERROR_INVALID_A },
	{ "header list missing",		ARC_SIGERROR_MISSING_H },
	{ "body length value invalid",		ARC_SIGERROR_INVALID_L },
	{ "query method invalid",		ARC_SIGERROR_INVALID_Q },
	{ "query option invalid",		ARC_SIGERROR_INVALID_QO },
	{ "domain tag missing",			ARC_SIGERROR_MISSING_D },
	{ "domain tag empty",			ARC_SIGERROR_EMPTY_D },
	{ "selector tag missing",		ARC_SIGERROR_MISSING_S },
	{ "selector tag empty",			ARC_SIGERROR_EMPTY_S },
	{ "signature data missing",		ARC_SIGERROR_MISSING_B },
	{ "signature data empty",		ARC_SIGERROR_EMPTY_B },
	{ "signature data corrupt",		ARC_SIGERROR_CORRUPT_B },
	{ "key not found in DNS",		ARC_SIGERROR_NOKEY },
	{ "key DNS reply corrupt",		ARC_SIGERROR_DNSSYNTAX },
	{ "key DNS query failed",		ARC_SIGERROR_KEYFAIL },
	{ "body hash missing",			ARC_SIGERROR_MISSING_BH },
	{ "body hash empty",			ARC_SIGERROR_EMPTY_BH },
	{ "body hash corrupt",			ARC_SIGERROR_CORRUPT_BH },
	{ "signature verification failed",	ARC_SIGERROR_BADSIG },
	{ "unauthorized subdomain",		ARC_SIGERROR_SUBDOMAIN },
	{ "multiple keys found",		ARC_SIGERROR_MULTIREPLY },
	{ "header list tag empty",		ARC_SIGERROR_EMPTY_H },
	{ "header list missing required entries", ARC_SIGERROR_INVALID_H },
	{ "length tag value exceeds body size", ARC_SIGERROR_TOOLARGE_L },
	{ "unprotected header field",		ARC_SIGERROR_MBSFAILED },
	{ "unknown key version",		ARC_SIGERROR_KEYVERSION },
	{ "unknown key hash",			ARC_SIGERROR_KEYUNKNOWNHASH },
	{ "signature-key hash mismatch",	ARC_SIGERROR_KEYHASHMISMATCH },
	{ "not an e-mail key",			ARC_SIGERROR_NOTEMAILKEY },
	{ "key type missing",			ARC_SIGERROR_KEYTYPEMISSING },
	{ "unknown key type",			ARC_SIGERROR_KEYTYPEUNKNOWN },
	{ "key revoked",			ARC_SIGERROR_KEYREVOKED },
	{ "unable to apply public key",		ARC_SIGERROR_KEYDECODE },
	{ "version missing",			ARC_SIGERROR_MISSING_V },
	{ "version empty",			ARC_SIGERROR_EMPTY_V },
	{ "signing key too small",		ARC_SIGERROR_KEYTOOSMALL },
	{ "duplicate instance",			ARC_SIGERROR_DUPINSTANCE },
	{ NULL,					-1 },
};
struct nametable *sigerrors = prv_sigerrors;

/* ===================================================================== */

/*
**  ARC_CODE_TO_NAME -- translate a mnemonic code to its name
**
**  Parameters:
**  	tbl -- name table
**  	code -- code to translate
**
**  Return value:
**  	Pointer to the name matching the provided code, or NULL if not found.
*/

const char *
arc_code_to_name(struct nametable *tbl, const int code)
{
	int c;

	assert(tbl != NULL);

	for (c = 0; ; c++)
	{
		if (tbl[c].tbl_code == -1 && tbl[c].tbl_name == NULL)
			return NULL;

		if (tbl[c].tbl_code == code)
			return tbl[c].tbl_name;
	}
}

/*
**  ARC_NAME_TO_CODE -- translate a name to a mnemonic code
**
**  Parameters:
**  	tbl -- name table
**  	name -- name to translate
**
**  Return value:
**  	A mnemonic code matching the provided name, or -1 if not found.
*/

const int
arc_name_to_code(struct nametable *tbl, const char *name)
{
	int c;

	assert(tbl != NULL);

	for (c = 0; ; c++)
	{
		if (tbl[c].tbl_code == -1 && tbl[c].tbl_name == NULL)
			return -1;

		if (strcasecmp(tbl[c].tbl_name, name) == 0)
			return tbl[c].tbl_code;
	}
}
