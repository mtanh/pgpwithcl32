/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2016					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
/* Suspend conversion of literals to ASCII. */
#pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
#pragma convert( 0 )
#endif /* IBM medium iron */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The tests that use databases and certificate stores require that the user
   set up a suitable ODBC data source (at least when running under Windows),
   to automate this process we try and create the data source if it isn't
   present.

   This is complicated by the fact that the universal default MSJET database
   driver doesn't have a 64-bit version so it's not possible to use it under
   Vista/Windows 7 x64.  To work around this we fall back to the SQL Server
   driver, which replaces MSJET on x64 systems */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN32_WCE )

#define DATABASE_AUTOCONFIG

#include <odbcinst.h>

   /* Default MS Access database */

#define DRIVER_NAME				TEXT( "Microsoft Access Driver (*.MDB)" )
#define DATABASE_ATTR_NAME		"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"DBQ="
#define DATABASE_ATTR_CREATE	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"CREATE_DB="
#define DATABASE_ATTR_TAIL		DATABASE_KEYSET_NAME_ASCII ".mdb#"
#define CERTSTORE_ATTR_NAME		"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"DBQ="
#define CERTSTORE_ATTR_CREATE	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"CREATE_DB="
#define CERTSTORE_ATTR_TAIL		CERTSTORE_KEYSET_NAME_ASCII ".mdb#"

/* Alternative 1, SQL Server */

#define DRIVER_NAME_ALT_1			TEXT( "SQL Server" )
#define DATABASE_ATTR_NAME_ALT_1	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Server=localhost#" \
									"Database="
#define DATABASE_ATTR_CREATE_ALT_1	""
#define DATABASE_ATTR_TAIL_ALT_1	DATABASE_KEYSET_NAME_ASCII "#"
#define CERTSTORE_ATTR_NAME_ALT_1	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Server=localhost#" \
									"Database="
#define CERTSTORE_ATTR_CREATE_ALT_1	""
#define CERTSTORE_ATTR_TAIL_ALT_1	CERTSTORE_KEYSET_NAME_ASCII "#"

/* Alternative 2, SQLite */

#define DRIVER_NAME_ALT_2			TEXT( "SQLite3 ODBC Driver" )
#define DATABASE_ATTR_NAME_ALT_2	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Database="
#define DATABASE_ATTR_CREATE_ALT_2	""
#define DATABASE_ATTR_TAIL_ALT_2	DATABASE_KEYSET_NAME_ASCII "#"
#define CERTSTORE_ATTR_NAME_ALT_2	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Database="
#define CERTSTORE_ATTR_CREATE_ALT_2	""
#define CERTSTORE_ATTR_TAIL_ALT_2	CERTSTORE_KEYSET_NAME_ASCII "#"

typedef enum {
	ODBC_SOURCE_ACCESS, ODBC_SOURCE_SQLSERVER,
	ODBC_SOURCE_SQLITE
} ODBC_SOURCE_TYPE;

static void buildDBString(char *buffer, const char *attrName,
	const char *attrTail, const char *path)
{
	const int attrNameSize = strlen(attrName);
	const int attrTailSize = strlen(attrTail) + 1;
	const int pathSize = strlen(path);
	int dbStringLen, i;

	/* Build up the data-source control string */
	memcpy(buffer, attrName, attrNameSize + 1);
	memcpy(buffer + attrNameSize, path, pathSize);
	if (attrTailSize > 0)
	{
		memcpy(buffer + attrNameSize + pathSize, attrTail,
			attrTailSize);
	}
	buffer[attrNameSize + pathSize + attrTailSize] = '\0';

	/* Finally, convert the strings to the weird embedded-null strings
	   required by SQLConfigDataSource() */
	dbStringLen = strlen(buffer);
	for (i = 0; i < dbStringLen; i++)
	{
		if (buffer[i] == '#')
			buffer[i] = '\0';
	}
}

static void reportSqlError(const ODBC_SOURCE_TYPE sourceType)
{
	DWORD dwErrorCode;
	WORD errorMessageLen;
	char errorMessage[256];

	if (SQLInstallerError(1, &dwErrorCode, errorMessage, 256,
		&errorMessageLen) != SQL_NO_DATA)
	{
		printf("SQLConfigDataSource() returned error code %d,\n  "
			"message '%s'.\n", dwErrorCode, errorMessage);
#if defined( _M_X64 )
		if (sourceType == ODBC_SOURCE_ACCESS)
		{
			puts("  (This is probably because there's no appropriate "
				"64-bit driver present,\n  retrying the create with "
				"an alternative driver...).");
		}
#endif /* _M_X64 */
	}
	else
	{
		puts("SQLConfigDataSource() failed, no additional information "
			"available");
	}
}

static BOOLEAN createDatabase(const char *driverName,
	const char *keysetName,
	const char *nameString,
	const char *createString,
	const char *trailerString,
	const ODBC_SOURCE_TYPE sourceType)
{
	char tempPathBuffer[512];
	char attrBuffer[1024];
#ifdef UNICODE_STRINGS
	wchar_t wcAttrBuffer[1024];
#endif /* UNICODE_STRINGS */
	int status;

	if (!GetTempPath(512, tempPathBuffer))
		strcpy(tempPathBuffer, "C:\\Temp\\");

	/* Try and create the DSN.  For the default Access driver his is a two-
	   step process, first we create the DSN and then the underlying file
	   that contains the database.  For SQL Server it's simpler, the database
	   server already exists so all we have to do is create the database */
	switch (sourceType)
	{
	case ODBC_SOURCE_ACCESS:
		printf("Database keyset '%s' not found, attempting to create\n  "
			"data source (ODBC - MS Access)...\n", keysetName);
		break;

	case ODBC_SOURCE_SQLSERVER:
		printf("Attempting to create keyset '%s' using alternative\n  "
			"data source (ODBC - SQL Server)...\n", keysetName);
		puts("  (Autoconfiguration of SQL Server data sources rather than "
			"having them\n  configured manually by an administrator can "
			"be erratic, if cryptlib\n  hangs while trying to access the "
			"certificate database then you need to\n  configure the SQL "
			"Server data source manually).");
		break;

	case ODBC_SOURCE_SQLITE:
		printf("Database keyset '%s' not found, attempting to create\n  "
			"data source (ODBC - SQLite)...\n", keysetName);
		break;
	}
	buildDBString(attrBuffer, nameString, trailerString, tempPathBuffer);
#ifdef UNICODE_STRINGS
	mbstowcs(wcAttrBuffer, attrBuffer, strlen(attrBuffer) + 1);
	status = SQLConfigDataSource(NULL, ODBC_ADD_DSN, driverName,
		wcAttrBuffer);
#else
	status = SQLConfigDataSource(NULL, ODBC_ADD_DSN, driverName,
		attrBuffer);
#endif /* UNICODE_STRINGS */
	if (status != 1)
	{
		reportSqlError(sourceType);
		return(FALSE);
	}
	if (sourceType != ODBC_SOURCE_ACCESS)
	{
		/* The server already exists and we're done */
		return(TRUE);
	}
	buildDBString(attrBuffer, createString, trailerString, tempPathBuffer);
#ifdef UNICODE_STRINGS
	mbstowcs(wcAttrBuffer, attrBuffer, strlen(attrBuffer) + 1);
	status = SQLConfigDataSource(NULL, ODBC_ADD_DSN, driverName,
		wcAttrBuffer);
#else
	status = SQLConfigDataSource(NULL, ODBC_ADD_DSN, driverName,
		attrBuffer);
#endif /* UNICODE_STRINGS */
	if (status != 1)
	{
		reportSqlError(sourceType);
		return(FALSE);
	}

	return(TRUE);
}

static void checkCreateDatabaseKeyset(void)
{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Check whether the test certificate database can be opened.  This can
	   return a CRYPT_ARGERROR_PARAM3 as a normal condition since a freshly-
	   created database is empty and therefore can't be identified as a
	   certificate database until data is written to it */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		CRYPT_KEYSET_ODBC, DATABASE_KEYSET_NAME,
		CRYPT_KEYOPT_READONLY);
	if (cryptStatusOK(status))
	{
		cryptKeysetClose(cryptKeyset);
		return;
	}
	if (status != CRYPT_ERROR_OPEN)
		return;

	/* Create the database keyset */
	status = createDatabase(DRIVER_NAME, DATABASE_KEYSET_NAME_ASCII,
		DATABASE_ATTR_NAME, DATABASE_ATTR_CREATE,
		DATABASE_ATTR_TAIL, ODBC_SOURCE_ACCESS);
	if (status == FALSE)
	{
		/* The create with the default MS Access driver failed, fall back to
		   the SQL Server alternative */
		status = createDatabase(DRIVER_NAME_ALT_1,
			DATABASE_KEYSET_NAME_ASCII,
			DATABASE_ATTR_NAME_ALT_1,
			DATABASE_ATTR_CREATE_ALT_1,
			DATABASE_ATTR_TAIL_ALT_1,
			ODBC_SOURCE_SQLITE);
	}
	if (status == FALSE)
	{
		/* The create failed as well, try SQLite */
		status = createDatabase(DRIVER_NAME_ALT_2,
			DATABASE_KEYSET_NAME_ASCII,
			DATABASE_ATTR_NAME_ALT_2,
			DATABASE_ATTR_CREATE_ALT_2,
			DATABASE_ATTR_TAIL_ALT_2,
			ODBC_SOURCE_SQLSERVER);
	}
	puts((status == TRUE) ? "Data source creation succeeded." : \
		"Data source creation failed.\n\nYou need to create the "
		"keyset data source as described in the cryptlib manual\n"
		"for the database keyset tests to run.");
}

static void checkCreateDatabaseCertstore(void)
{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Check whether the test certificate store database can be opened.
	   This can return a CRYPT_ARGERROR_PARAM3 as a normal condition since a
	   freshly-created database is empty and therefore can't be identified
	   as a certificate store until data is written to it */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		CRYPT_KEYSET_ODBC_STORE, CERTSTORE_KEYSET_NAME,
		CRYPT_KEYOPT_READONLY);
	if (cryptStatusOK(status))
	{
		cryptKeysetClose(cryptKeyset);
		return;
	}
	if (status != CRYPT_ERROR_OPEN)
		return;

	/* Create the database keyset */
	status = createDatabase(DRIVER_NAME, CERTSTORE_KEYSET_NAME_ASCII,
		CERTSTORE_ATTR_NAME, CERTSTORE_ATTR_CREATE,
		CERTSTORE_ATTR_TAIL, FALSE);
	if (status == FALSE)
	{
		/* The create with the default MS Access driver failed, fall back to
		   the SQL Server alternative */
		status = createDatabase(DRIVER_NAME_ALT_1, CERTSTORE_KEYSET_NAME_ASCII,
			CERTSTORE_ATTR_NAME_ALT_1,
			CERTSTORE_ATTR_CREATE_ALT_1,
			CERTSTORE_ATTR_TAIL_ALT_1, TRUE);
	}
	if (status == FALSE)
	{
		/* The create failed as well, try SQLite */
		status = createDatabase(DRIVER_NAME_ALT_2, CERTSTORE_KEYSET_NAME_ASCII,
			CERTSTORE_ATTR_NAME_ALT_2,
			CERTSTORE_ATTR_CREATE_ALT_2,
			CERTSTORE_ATTR_TAIL_ALT_2, TRUE);
	}
	puts((status == TRUE) ? "Data source creation succeeded.\n" : \
		"Data source creation failed.\n\nYou need to create the "
		"certificate store data source as described in the\n"
		"cryptlib manual for the certificate management tests to "
		"run.\n");
}

void checkCreateDatabaseKeysets(void)
{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Create the databases */
	checkCreateDatabaseKeyset();
	checkCreateDatabaseCertstore();

	/* Create the keysets within the database */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
		CRYPT_KEYOPT_CREATE);
	if (cryptStatusOK(status))
	{
		printf("Database keyset created within database '%s'.\n",
			DATABASE_KEYSET_NAME);
		cryptKeysetClose(cryptKeyset);
	}
	else
	{
		if (status != CRYPT_ERROR_DUPLICATE)
		{
			printf("Error %d creating keyset within '%s' database.\n", status,
				DATABASE_KEYSET_NAME);
		}
	}
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
		CRYPT_KEYOPT_CREATE);
	if (cryptStatusOK(status))
	{
		printf("Certificate store keyset created within database '%s'.\n",
			CERTSTORE_KEYSET_NAME);
		cryptKeysetClose(cryptKeyset);
	}
	else
	{
		if (status != CRYPT_ERROR_DUPLICATE)
		{
			printf("Error %d creating keyset within '%s' database.\n", status,
				CERTSTORE_KEYSET_NAME);
		}
	}
	putchar('\n');
}

/* External-access function for situations where a database keyset is
   needed, for example the PKI session tests */

void initDatabaseKeysets(void)
{
	/* Create the certificate store database if required */
	checkCreateDatabaseCertstore();
}
#endif /* Win32 with VC++ */

/****************************************************************************
*																			*
*							Test Low-level Functions						*
*																			*
****************************************************************************/

#ifdef TEST_SELFTEST

/* Test the cryptlib self-test routines */

BOOLEAN testSelfTest(void)
{
	int value, status;

	/* Perform the self-test.  First we write the value to true to force a
	   self-test, then we read it back to see whether it succeeded */
	status = cryptSetAttribute(CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK,
		TRUE);
	if (cryptStatusError(status))
	{
		fprintf(outputStream, "Attempt to perform cryptlib algorithm "
			"self-test failed with error code %d, line %d.\n", status,
			__LINE__);
		return(FALSE);
	}
	status = cryptGetAttribute(CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK,
		&value);
	if (cryptStatusError(status) || value != TRUE)
	{
		/* Unfortunately all that we can report at this point is that the
		   self-test failed, we can't try each algorithm individually
		   because the self-test has disabled the failed one(s) */
		fprintf(outputStream, "cryptlib algorithm self-test failed, line "
			"%d.\n", __LINE__);
		return(FALSE);
	}
	fputs("cryptlib algorithm self-test succeeded.\n\n", outputStream);

	return(TRUE);
}
#else

BOOLEAN testSelfTest(void)
{
	puts("Skipping test of self-test routines...\n");
	return(TRUE);
}
#endif /* TEST_SELFTEST */

#ifdef TEST_LOWLEVEL

/* Test the low-level encryption routines */

BOOLEAN testLowLevel(void)
{
	CRYPT_ALGO_TYPE cryptAlgo;
	BOOLEAN algosEnabled;

	/* Test the conventional encryption routines */
	algosEnabled = FALSE;
	for (cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++)
	{
		if (cryptStatusOK(cryptQueryCapability(cryptAlgo, NULL)))
		{
			if (!testLowlevel(CRYPT_UNUSED, cryptAlgo, FALSE))
				return(FALSE);
			algosEnabled = TRUE;
		}
	}
	if (!algosEnabled)
		puts("(No conventional-encryption algorithms enabled).");

	/* Test the public-key encryption routines */
	algosEnabled = FALSE;
	for (cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++)
	{
		if (cryptStatusOK(cryptQueryCapability(cryptAlgo, NULL)))
		{
			if (!testLowlevel(CRYPT_UNUSED, cryptAlgo, FALSE))
				return(FALSE);
			algosEnabled = TRUE;
		}
	}
	if (cryptStatusOK(cryptQueryCapability(CRYPT_ALGO_RSA, NULL)) && \
		!testRSAMinimalKey())
		return(FALSE);
	if (!algosEnabled)
		puts("(No public-key algorithms enabled).");

	/* Test the hash routines */
	algosEnabled = FALSE;
	for (cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++)
	{
		if (cryptStatusOK(cryptQueryCapability(cryptAlgo, NULL)))
		{
			if (!testLowlevel(CRYPT_UNUSED, cryptAlgo, FALSE))
				return(FALSE);
			algosEnabled = TRUE;
		}
	}
	if (!algosEnabled)
		puts("(No hash algorithms enabled).");

	/* Test the MAC routines */
	algosEnabled = FALSE;
	for (cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++)
	{
		if (cryptStatusOK(cryptQueryCapability(cryptAlgo, NULL)))
		{
			if (!testLowlevel(CRYPT_UNUSED, cryptAlgo, FALSE))
				return(FALSE);
			algosEnabled = TRUE;
		}
	}
	if (!algosEnabled)
		puts("(No MAC algorithms enabled).");
	printf("\n");

	return(TRUE);
}
#else

BOOLEAN testLowLevel(void)
{
	puts("Skipping test of low-level encryption routines...\n");
	return(TRUE);
}
#endif /* TEST_LOWLEVEL */

/****************************************************************************
*																			*
*					Test Randomness, Config, and Device Functions			*
*																			*
****************************************************************************/

#ifdef TEST_RANDOM

/* Test the randomness-gathering routines */

BOOLEAN testRandom(void)
{
	if (!testRandomRoutines())
	{
		fputs("The self-test will proceed without using a strong random "
			"number source.\n\n", outputStream);

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom("xyzzy", 5);
	}

	return(TRUE);
}
#else

BOOLEAN testRandom(void)
{
	puts("Skipping test of randomness routines...\n");
	return(TRUE);
}
#endif /* TEST_RANDOM */

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_ATTRIBUTE_TYPE option;	/* Option */
	const char FAR_DATA *name;			/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
} FAR_DATA configOption[] = {
{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },
{ CRYPT_OPTION_INFO_STEPPING, "CRYPT_OPTION_INFO_STEPPING", TRUE },

{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },
{ CRYPT_OPTION_ENCR_MAC, "CRYPT_OPTION_ENCR_MAC", TRUE },

{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },

{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
{ CRYPT_OPTION_CERT_COMPLIANCELEVEL, "CRYPT_OPTION_CERT_COMPLIANCELEVEL", TRUE },
{ CRYPT_OPTION_CERT_REQUIREPOLICY, "CRYPT_OPTION_CERT_REQUIREPOLICY", TRUE },

{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, "CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE", TRUE },
{ CRYPT_OPTION_KEYS_LDAP_FILTER, "CRYPT_OPTION_KEYS_LDAP_FILTER", FALSE },
{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, "CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY", TRUE },

{ CRYPT_OPTION_NET_SOCKS_SERVER, "CRYPT_OPTION_NET_SOCKS_SERVER", FALSE },
{ CRYPT_OPTION_NET_SOCKS_USERNAME, "CRYPT_OPTION_NET_SOCKS_USERNAME", FALSE },
{ CRYPT_OPTION_NET_HTTP_PROXY, "CRYPT_OPTION_NET_HTTP_PROXY", FALSE },
{ CRYPT_OPTION_NET_CONNECTTIMEOUT, "CRYPT_OPTION_NET_CONNECTTIMEOUT", TRUE },
{ CRYPT_OPTION_NET_READTIMEOUT, "CRYPT_OPTION_NET_READTIMEOUT", TRUE },
{ CRYPT_OPTION_NET_WRITETIMEOUT, "CRYPT_OPTION_NET_WRITETIMEOUT", TRUE },

{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
{ CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, "CRYPT_OPTION_MISC_SIDECHANNELPROTECTION", TRUE },

{ CRYPT_ATTRIBUTE_NONE, NULL, 0 }
};

/* Test the configuration options routines */

BOOLEAN testConfig(void)
{
	int i, value, status;

	for (i = 0; configOption[i].option != CRYPT_ATTRIBUTE_NONE; i++)
	{
		C_CHR buffer[256];
		int length;

		if (configOption[i].isNumeric)
		{
			status = cryptGetAttribute(CRYPT_UNUSED,
				configOption[i].option, &value);
			if (cryptStatusError(status))
			{
				fprintf(outputStream, "%s appears to be "
					"disabled/unavailable in this build.\n",
					configOption[i].name);
				continue;
			}
			fprintf(outputStream, "%s = %d.\n", configOption[i].name,
				value);
			continue;
		}
		status = cryptGetAttributeString(CRYPT_UNUSED,
			configOption[i].option,
			buffer, &length);
		if (cryptStatusError(status))
		{
			fprintf(outputStream, "%s appears to be disabled/unavailable "
				"in this build.\n", configOption[i].name);
			continue;
		}
		assert(length < 256);
#ifdef UNICODE_STRINGS
		buffer[length / sizeof(wchar_t)] = TEXT('\0');
		fprintf(outputStream, "%s = %S.\n", configOption[i].name,
			buffer);
#else
		buffer[length] = '\0';
		fprintf(outputStream, "%s = %s.\n", configOption[i].name,
			buffer);
#endif /* UNICODE_STRINGS */
	}
	printf("\n");

	return(TRUE);
}
#else

BOOLEAN testConfig(void)
{
	puts("Skipping display of config options...\n");
	return(TRUE);
}
#endif /* TEST_CONFIG */

#ifdef TEST_DEVICE

/* Test the crypto device routines */

BOOLEAN testDevice(void)
{
	int status;

	status = testDevices();
	if (status == CRYPT_ERROR_NOTAVAIL)
	{
		puts("Handling for crypto devices doesn't appear to be enabled in "
			"this build of\ncryptlib.\n");
		return(TRUE);
	}
	if (!status)
		return(FALSE);

	return(TRUE);
}
#else

BOOLEAN testDevice(void)
{
	fputs("Skipping test of crypto device routines...\n", outputStream);
	return(TRUE);
}
#endif /* TEST_DEVICE */

/****************************************************************************
*																			*
*							Test Mid/High-level Functions					*
*																			*
****************************************************************************/

#ifdef TEST_MIDLEVEL

/* Test the mid-level routines */

BOOLEAN testMidLevel(void)
{
	if (!testLargeBufferEncrypt())
		return(FALSE);
	if (!testDeriveKey())
		return(FALSE);
	if (!testConventionalExportImport())
		return(FALSE);
	if (cryptStatusOK(cryptQueryCapability(CRYPT_ALGO_HMAC_SHA1, NULL)))
	{
		/* Only test the MAC functions of HMAC-SHA1 is enabled */
		if (!testMACExportImport())
			return(FALSE);
	}
	if (cryptStatusOK(cryptQueryCapability(CRYPT_ALGO_RSA, NULL)))
	{
		/* Only test the PKC functions if RSA is enabled */
		if (!testKeyExportImport())
			return(FALSE);
		if (!testSignData())
			return(FALSE);
		if (!testKeygen())
			return(FALSE);
	}
	if (!testMidLevelDebugCheck())
		return(FALSE);
	/* No need for putchar, mid-level functions leave a blank line at end */

	return(TRUE);
}
#else

BOOLEAN testMidLevel(void)
{
	puts("Skipping test of mid-level encryption routines...\n");
	return(TRUE);
}
#endif /* TEST_MIDLEVEL */

#ifdef TEST_HIGHLEVEL

/* Test the high-level routines (these are similar to the mid-level routines
   but rely on things like certificate management to work) */

BOOLEAN testHighLevel(void)
{
	if (!testKeyExportImportCMS())
		return(FALSE);
	if (!testSignDataCMS())
		return(FALSE);

	return(TRUE);
}
#else

BOOLEAN testHighLevel(void)
{
	puts("Skipping test of high-level routines...\n");
	return(TRUE);
}
#endif /* TEST_HIGHLEVEL */

/****************************************************************************
*																			*
*								Test Certificates							*
*																			*
****************************************************************************/

#ifdef TEST_CERT

/* Test the certificate routines */

BOOLEAN testCert(void)
{
	if (!testBasicCert())
		return(FALSE);
	if (!testCACert())
		return(FALSE);
	if (!testXyzzyCert())
		return(FALSE);
	if (!testTextStringCert())
		return(FALSE);
	if (!testComplexCert())
		return(FALSE);
	if (!testAltnameCert())
		return(FALSE);
	if (!testCertExtension())
		return(FALSE);
	if (!testCustomDNCert())
		return(FALSE);
	if (!testSETCert())
		return(FALSE);
	if (!testAttributeCert())
		return(FALSE);
	if (!testCertRequest())
		return(FALSE);
	if (!testComplexCertRequest())
		return(FALSE);
	if (!testCertRequestAttrib())
		return(FALSE);
	if (!testCRMFRequest())
		return(FALSE);
	if (!testComplexCRMFRequest())
		return(FALSE);
	if (!testCRL())
		return(FALSE);
	if (!testComplexCRL())
		return(FALSE);
	if (!testRevRequest())
		return(FALSE);
	if (!testCertChain())
		return(FALSE);
	if (!testCMSAttributes())
		return(FALSE);
	if (!testOCSPReqResp())
		return(FALSE);
	if (!testCertImport())
		return(FALSE);
	if (!testCertImportECC())
		return(FALSE);
	if (!testCertReqImport())
		return(FALSE);
	if (!testCRLImport())
		return(FALSE);
	if (!testCertChainImport())
		return(FALSE);
	if (!testOCSPImport())
		return(FALSE);
	if (!testBase64CertImport())
		return(FALSE);
	if (!testBase64CertChainImport())
		return(FALSE);
	if (!testMiscImport())
		return(FALSE);
	if (!testNonchainCert())
		return(FALSE);
	if (!testCertComplianceLevel())
		return(FALSE);
	if (!testCertChainHandling())
		return(FALSE);
	if (!testPKCS1Padding())
		return(FALSE);
#if 0	/* This takes a while to run and produces a lot of output that won't
		   be meaningful to anyone other than cryptlib developers so it's
		   disabled by default */
	if (!testPathProcessing())
		return(FALSE);
#endif /* 0 */

	return(TRUE);
}
#else

BOOLEAN testCert(void)
{
	puts("Skipping test of certificate routines...\n");
	return(TRUE);
}
#endif /* TEST_CERT */

#ifdef TEST_CERTPROCESS

/* Test the certificate processing and CA certificate management
   functionality.  A side-effect of the certificate-management
   functionality is that the OCSP EE test certificates are written
   to the test data directory */

BOOLEAN testCertMgmt(void)
{
	int status;

	if (!testCertProcess())
		return(FALSE);
	status = testCertManagement();
	if (status == CRYPT_ERROR_NOTAVAIL)
	{
		puts("Handling for CA certificate stores doesn't appear to be "
			"enabled in this\nbuild of cryptlib, skipping the test of "
			"the certificate management routines.\n");
	}
	else
	{
		if (!status)
			return(FALSE);
	}

	return(TRUE);
}
#else

BOOLEAN testCertMgmt(void)
{
	puts("Skipping test of certificate handling/CA management...\n");
	return(TRUE);
}
#endif /* TEST_CERTPROCESS */

/****************************************************************************
*																			*
*								Test Keysets								*
*																			*
****************************************************************************/

#ifdef TEST_KEYSET

/* Test the file and database keyset read routines */

BOOLEAN testKeysetFile(void)
{
	if (!testGetPGPPublicKey())
		return(FALSE);
	if (!testGetPGPPrivateKey())
		return(FALSE);
	if (!testReadWriteFileKey())
		return(FALSE);
	if (!testReadWriteAltFileKey())
		return(FALSE);
	if (!testReadWritePGPFileKey())
		return(FALSE);
	if (!testImportFileKey())
		return(FALSE);
	if (!testReadFilePublicKey())
		return(FALSE);
	if (!testDeleteFileKey())
		return(FALSE);
	if (!testUpdateFileCert())
		return(FALSE);
	if (!testReadFileCert())
		return(FALSE);
	if (!testReadFileCertPrivkey())
		return(FALSE);
	if (!testWriteFileCertChain())
		return(FALSE);
	if (!testReadFileCertChain())
		return(FALSE);
	if (!testAddTrustedCert())
		return(FALSE);
#if 0	/* This changes the global config file and is disabled by default */
	if (!testAddGloballyTrustedCert())
		return(FALSE);
#endif /* 0 */
	if (!testWriteFileLongCertChain())
		return(FALSE);
	if (!testSingleStepFileCert())
		return(FALSE);
	if (!testSingleStepAltFileCert())
		return(FALSE);
	if (!testDoubleCertFile())
		return(FALSE);
	if (!testRenewedCertFile())
		return(FALSE);
	if (!testReadAltFileKey())
		return(FALSE);
	if (!testReadMiscFile())
		return(FALSE);
	return(TRUE);
}

BOOLEAN testKeysetDatabase(void)
{
	int status;

#ifdef DATABASE_AUTOCONFIG
	checkCreateDatabaseKeysets();
#endif /* DATABASE_AUTOCONFIG */
	status = testWriteCert();
	if (!status)
		return(FALSE);
	if (status == CRYPT_ERROR_NOTAVAIL)
	{
		puts("Handling for certificate databases doesn't appear to be "
			"enabled in this\nbuild of cryptlib, skipping the test of "
			"the certificate database routines.\n");
	}
	else
	{
		/* The write succeeded, try and read back what we've written */
		if (!testReadCert())
			return(FALSE);
		if (!testKeysetQuery())
			return(FALSE);
	}

	/* For the following tests we may have read access but not write access,
	   so we test a read of known-present certs before trying a write -
	   unlike the local keysets we don't need to add a certificate before we
	   can try reading it */
	status = testReadCertLDAP();
	if (status == CRYPT_ERROR_NOTAVAIL)
	{
		puts("Handling for LDAP certificate directories doesn't appear to "
			"be enabled in\nthis build of cryptlib, skipping the test of "
			"the certificate directory\nroutines.\n");
	}
	else
	{
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if (status)
		{
			/* LDAP writes are even worse than LDAP reads, so we don't
			   treat failures here as fatal either */
			(void)testWriteCertLDAP();
		}
	}
	status = testReadCertURL();
	if (status == CRYPT_ERROR_NOTAVAIL)
	{
		puts("Handling for fetching certificates from web pages doesn't "
			"appear to be\nenabled in this build of cryptlib, skipping "
			"the test of the HTTP routines.\n");
	}
	else
	{
		/* Being able to read a certificate from a web page is rather
		   different from access to an HTTP certificate store so we don't
		   treat an error here as fatal */
		if (status)
			(void)testReadCertHTTP();
	}

	return(TRUE);
}
#else

BOOLEAN testKeysetFile(void)
{
	puts("Skipping test of file keyset read routines...\n");
	return(TRUE);
}

BOOLEAN testKeysetDatabase(void)
{
	puts("Skipping test of database keyset read routines...\n");
	return(TRUE);
}
#endif /* TEST_KEYSET */

/****************************************************************************
*																			*
*								Test Enveloping								*
*																			*
****************************************************************************/

#ifdef TEST_ENVELOPE

/* Test the enveloping routines */

BOOLEAN testEnveloping(void)
{
	if (!testEnvelopeData())
		return(FALSE);
	if (!testEnvelopeDataLargeBuffer())
		return(FALSE);
	if (!testEnvelopeCompress())
		return(FALSE);
	if (!testPGPEnvelopeCompressedDataImport())
		return(FALSE);
	if (!testEnvelopeSessionCrypt())
		return(FALSE);
	if (!testEnvelopeSessionCryptLargeBuffer())
		return(FALSE);
	if (!testEnvelopeCrypt())
		return(FALSE);
	if (!testEnvelopePasswordCrypt())
		return(FALSE);
	if (!testEnvelopePasswordCryptBoundary())
		return(FALSE);
	if (!testEnvelopePasswordCryptImport())
		return(FALSE);
	if (!testPGPEnvelopePasswordCryptImport())
		return(FALSE);
	if (!testEnvelopePKCCrypt())
		return(FALSE);
	if (!testEnvelopePKCCryptAlgo())
		return(FALSE);
	if (!testPGPEnvelopePKCCryptImport())
		return(FALSE);
	if (!testEnvelopePKCIterated())
		return(FALSE);
	if (!testEnvelopeSign())
		return(FALSE);
	if (!testEnvelopeSignAlgos())
		return(FALSE);
	if (!testEnvelopeSignHashUpgrade())
		return(FALSE);
	if (!testEnvelopeSignOverflow())
		return(FALSE);
	if (!testEnvelopeSignIndef())
		return(FALSE);
	if (!testPGPEnvelopeSignedDataImport())
		return(FALSE);
	if (!testEnvelopeAuthenticate())
		return(FALSE);
	if (!testEnvelopeAuthEnc())
		return(FALSE);
	if (!testCMSEnvelopePKCCrypt())
		return(FALSE);
	if (!testCMSEnvelopePKCCryptDoubleCert())
		return(FALSE);
	if (!testCMSEnvelopePKCCryptImport())
		return(FALSE);
	if (!testCMSEnvelopeSign())
		return(FALSE);
	if (!testCMSEnvelopeDualSign())
		return(FALSE);
	if (!testCMSEnvelopeDetachedSig())
		return(FALSE);
	if (!testCMSEnvelopeRefCount())
		return(FALSE);
	if (!testCMSEnvelopeSignedDataImport())
		return(FALSE);
	if (!testEnvelopeCMSDebugCheck())
		return(FALSE);
	if (!testEnvelopePGPDebugCheck())
		return(FALSE);

	return(TRUE);
}
#else

BOOLEAN testEnveloping(void)
{
	puts("Skipping test of enveloping routines...\n");
	return(TRUE);
}
#endif /* TEST_ENVELOPE */

/****************************************************************************
*																			*
*								Test Sessions								*
*																			*
****************************************************************************/

#ifdef TEST_SESSION

/* Test the session routines */

BOOLEAN testSessions(void)
{
	int status;

	status = testSessionUrlParse();
	if (!status)
		return(FALSE);
	if (status == CRYPT_ERROR_NOTAVAIL)
	{
		puts("Network access doesn't appear to be enabled in this build of "
			"cryptlib,\nskipping the test of the secure session routines.\n");
		return(TRUE);
	}
	if (!checkNetworkAccess())
	{
		puts("Couldn't perform a test connect to a well-known site "
			"(Amazon.com) which\nindicates that external network access "
			"isn't available.  Is this machine\nsituated behind a "
			"firewall?\n");
		return(FALSE);
	}
	if (!testSessionAttributes())
		return(FALSE);
	if (!testSessionSSH())
		return(FALSE);
	if (!testSessionSSHPubkeyAuth())
		return(FALSE);
	if (!testSessionSSHPortforward())
		return(FALSE);
	if (!testSessionSSHExec())
		return(FALSE);
	if (!testSessionSSL())
		return(FALSE);
	if (!testSessionSSLLocalSocket())
		return(FALSE);
	if (!testSessionTLS())
		return(FALSE);
	if (!testSessionTLSLocalSocket())
		return(FALSE);
	if (!testSessionTLS11())
		return(FALSE);
	if (!testSessionTLS12())
		return(FALSE);
#if 0	/* The MS test server used for the general TLS 1.2 tests requires 
		   fairly extensive custom configuration of client certs and the
		   ability to do rehandshakes due to the oddball way that SChannel
		   handles client auth so we disable this test until another server
		   that does TLS 1.2 client auth less awkwardly appears */
	if (!testSessionTLS12ClientCert())
		return(FALSE);
#endif /* 0 */
	if (!testSessionOCSP())
		return(FALSE);
	if (!testSessionTSP())
		return(FALSE);
	if (!testSessionEnvTSP())
		return(FALSE);
	if (!testSessionCMP())
		return(FALSE);

	return(TRUE);
}
#else

BOOLEAN testSessions(void)
{
	puts("Skipping test of session routines...\n");
	return(TRUE);
}
#endif /* TEST_SESSION */

#ifdef TEST_SESSION_LOOPBACK

/* Test loopback client/server sessions.  These require a threaded OS and
   are aliased to no-ops on non-threaded systems.  In addition there can be
   synchronisation problems between the two threads if the server is delayed
   for some reason, resulting in the client waiting for a socket that isn't
   opened yet.  This isn't easy to fix without a lot of explicit intra-
   thread synchronisation, if there's a problem it's easier to just re-run
   the tests */

BOOLEAN testSessionsLoopback(void)
{
#ifdef DATABASE_AUTOCONFIG
	checkCreateDatabaseKeysets();	/* Needed for PKI tests */
#endif /* DATABASE_AUTOCONFIG */
	if (!testSessionSSHClientServer())
		return(FALSE);
	if (!testSessionSSHClientServerDsaKey())
		return(FALSE);
	if (!testSessionSSHClientServerEccKey())
		return(FALSE);
	if (!testSessionSSHClientServerFingerprint())
		return(FALSE);
	if (!testSessionSSHClientServerPubkeyAuth())
		return(FALSE);
	if (!testSessionSSHClientServerPortForward())
		return(FALSE);
	if (!testSessionSSHClientServerExec())
		return(FALSE);
	if (!testSessionSSHClientServerMultichannel())
		return(FALSE);
	if (!testSessionSSHClientServerDebugCheck())
		return(FALSE);
	if (!testSessionSSLClientServer())
		return(FALSE);
	if (!testSessionSSLClientCertClientServer())
		return(FALSE);
	if (!testSessionTLSClientServer())
		return(FALSE);
	if (!testSessionTLSSharedKeyClientServer())
		return(FALSE);
	if (!testSessionTLSNoSharedKeyClientServer())
		return(FALSE);
	if (!testSessionTLSBulkTransferClientServer())
		return(FALSE);
	if (!testSessionTLS11ClientServer())
		return(FALSE);
	if (!testSessionTLS11ClientCertClientServer())
		return(FALSE);
	if (!testSessionTLS12ClientServer())
		return(FALSE);
	if (!testSessionTLS12ClientCertClientServer())
		return(FALSE);
	if (!testSessionTLS12ClientCertManualClientServer())
		return(FALSE);
	if (!testSessionSSLClientServerDebugCheck())
		return(FALSE);
	if (!testSessionHTTPCertstoreClientServer())
		return(FALSE);
	if (!testSessionRTCSClientServer())
		return(FALSE);
	if (!testSessionOCSPClientServer())
		return(FALSE);
	if (!testSessionOCSPMulticertClientServer())
		return(FALSE);
	if (!testSessionTSPClientServer())
		return(FALSE);
	if (!testSessionTSPClientServerPersistent())
		return(FALSE);
	if (!testSessionSCEPClientServer())
		return(FALSE);
	if (!testSessionSCEPCACertClientServer())
		return(FALSE);
#if 0	/* Requires changes to the SCEP specification */
	if (!testSessionSCEPRenewClientServer())
		return(FALSE);
#endif /* 0 */
	if (!testSessionSCEPClientServerDebugCheck())
		return(FALSE);
	if (!testSessionCMPClientServer())
		return(FALSE);
	if (!testSessionCMPSHA2ClientServer())
		return(FALSE);
	if (!testSessionCMPPKIBootClientServer())
		return(FALSE);
	if (!testSessionPNPPKIClientServer())
		return(FALSE);
	if (!testSessionPNPPKICAClientServer())
		return(FALSE);
#if 0	/* Full RA functionality not completely implemented yet */
	if (!testSessionCMPRAClientServer())
		return(FALSE);
#endif /* 0 */
	if (!testSessionCMPFailClientServer())
		return(FALSE);
	if (!testSessionCMPClientServerDebugCheck())
		return(FALSE);

	/* The final set of loopback tests, which spawn a large number of
	   threads, can be somewhat alarming due to the amount of message spew
	   that they produce so we only run them on one specific development
	   test machine */
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE ) && 0
	{
		char name[MAX_COMPUTERNAME_LENGTH + 1];
		int length = MAX_COMPUTERNAME_LENGTH + 1;

		if (GetComputerName(name, &length) && length == 8 && \
			!memcmp(name, "LENOVOX1", length))
		{
			if (!testSessionSSHClientServerDualThread())
				return(FALSE);
			if (!testSessionSSHClientServerMultiThread())
				return(FALSE);
			if (!testSessionTLSClientServerMultiThread())
				return(FALSE);
		}
	}
#endif /* __WINDOWS__ && !WinCE */
	return(TRUE);
}
#else

BOOLEAN testSessionsLoopback(void)
{
	puts("Skipping test of session routines...\n");
	return(TRUE);
}
#endif /* TEST_SESSION_LOOPBACK */

/****************************************************************************
*																			*
*								Test Users									*
*																			*
****************************************************************************/

#ifdef TEST_USER

/* Test the user routines */

BOOLEAN testUsers(void)
{
	if (!testUser())
		return(FALSE);

	return(TRUE);
}
#else

/* DICENTRAL CODE BLOCK */

#ifndef DIC_BUFFSZ
#define DIC_BUFFSZ 2048
#endif // !DIC_BUFFSZ

#define DIC_SUCCESS 1
#define DIC_ERROR 0
#define DIC_PGPKEYFILE "D:\\pgpauthen"

int publishPublicKey(const char *publicKeysetName,
	const CRYPT_CERTIFICATE cryptCertificate)
{
	CRYPT_KEYSET cryptKeyset;
	char name[128];
	int nameLen, status;
	/* Open a connection to the public-key keyset */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		CRYPT_KEYSET_ODBC, publicKeysetName, CRYPT_KEYOPT_NONE);
	if (cryptStatusError(status))
		return(status);
	/* Clear any existing certificates under this name that may already
	be present. This is useful for the sample code when re-running
	it multiple times and creating new keys on each run */
	status = cryptGetAttributeString(cryptCertificate,
		CRYPT_CERTINFO_COMMONNAME, name, &nameLen);
	if (cryptStatusOK(status))
	{
		name[nameLen] = '\0';
		(void)cryptDeleteKey(cryptKeyset, CRYPT_KEYID_NAME, name);
	}
	/* Publish the certificate to the keyset */
	status = cryptAddPublicKey(cryptKeyset, cryptCertificate);
	cryptKeysetClose(cryptKeyset);
	return(status);
}

int createSimplifiedCert(CRYPT_CERTIFICATE *userCertificate,
	const CRYPT_CONTEXT certKey,
	const char *certOwnerName,
	const char *certOwnerEmail,
	const char *certOwnerDNSName)
{
	CRYPT_CERTIFICATE cryptCertificate;
	int status;
	/* Clear the return value */
	*userCertificate = -1;
	/* Create a certificate and mark it as a simplified certificate */
	status = cryptCreateCert(&cryptCertificate, CRYPT_UNUSED,
		CRYPT_CERTTYPE_CERTIFICATE);
	if (cryptStatusError(status))
		return(status);

	status = cryptSetAttribute(cryptCertificate, CRYPT_CERTINFO_XYZZY, 1);
	if (cryptStatusError(status))
	{
		cryptDestroyCert(cryptCertificate);
		return(status);
	}
	/* Add the public key */
	status = cryptSetAttribute(cryptCertificate,
		CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, certKey);
	if (cryptStatusError(status))
	{
		cryptDestroyCert(cryptCertificate);
		return(status);
	}
	/* Add the various user identification components */
	status = cryptSetAttributeString(cryptCertificate,
		CRYPT_CERTINFO_COMMONNAME, certOwnerName,
		strlen(certOwnerName));
	if (cryptStatusOK(status) && certOwnerEmail != NULL)
	{
		status = cryptSetAttributeString(cryptCertificate,
			CRYPT_CERTINFO_EMAIL, certOwnerEmail,
			strlen(certOwnerEmail));
	}
	if (cryptStatusOK(status) && certOwnerDNSName != NULL)
	{
		status = cryptSetAttributeString(cryptCertificate,
			CRYPT_CERTINFO_DNSNAME, certOwnerDNSName,
			strlen(certOwnerDNSName));
	}
	if (cryptStatusOK(status))
	{
		/* Working with alternative name components like email addresses
		and DNS names moves the certificate cursor away from the DN,
		in case access to the DN will be required later on we move it
		back */
		status = cryptSetAttribute(cryptCertificate,
			CRYPT_ATTRIBUTE_CURRENT, CRYPT_CERTINFO_SUBJECTNAME);
	}
	if (cryptStatusError(status))
	{
		cryptDestroyCert(cryptCertificate);
		return(status);
	}
	/* Sign the certificate with the private key */
	status = cryptSignCert(cryptCertificate, certKey);
	if (cryptStatusError(status))
	{
		cryptDestroyCert(cryptCertificate);
		return(status);
	}
	/* Return the newly-created certificate to the caller */
	*userCertificate = cryptCertificate;
	return(CRYPT_OK);
}

int generateKey(const char *keyOwnerName,
	const char *keyOwnerEmail,
	const char *keyOwnerDNSName,
	const char *keyLabel,
	const char *privKeysetName,
	const char *privKeyPassword,
	const char *pubKeysetName)
{
	CRYPT_CONTEXT cryptContext;
	CRYPT_CERTIFICATE cryptCertificate;
	CRYPT_KEYSET cryptKeyset;
	int status;
	/* Generate a key */
	status = cryptCreateContext(&cryptContext, CRYPT_UNUSED,
		CRYPT_ALGO_RSA);
	if (cryptStatusError(status))
		return(status);

	status = cryptSetAttributeString(cryptContext,
		CRYPT_CTXINFO_LABEL, keyLabel, strlen(keyLabel));
	if (cryptStatusOK(status))
		status = cryptGenerateKey(cryptContext);

	if (cryptStatusError(status))
	{
		cryptDestroyContext(cryptContext);
		return(status);
	}
	/* Create a simplified certificate for it */
	status = createSimplifiedCert(&cryptCertificate, cryptContext,
		keyOwnerName, keyOwnerEmail, keyOwnerDNSName);
	if (cryptStatusError(status))
	{
		cryptDestroyContext(cryptContext);
		return(status);
	}
	/* Create a new keyset and write the key and certificate to it */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		CRYPT_KEYSET_FILE, privKeysetName, CRYPT_KEYOPT_CREATE);
	if (cryptStatusOK(status))
	{
		status = cryptAddPrivateKey(cryptKeyset, cryptContext,
			privKeyPassword);
		if (cryptStatusOK(status))
			status = cryptAddPublicKey(cryptKeyset, cryptCertificate/*cryptContext*/);
		cryptKeysetClose(cryptKeyset);
	}
	if (cryptStatusOK(status))
		status = publishPublicKey(pubKeysetName, cryptCertificate);
	/* Clean up */
	cryptDestroyContext(cryptContext);
	cryptDestroyCert(cryptCertificate);
	return(status);
}

int dicGenerateKey(OUT const char* keyFile)
{
	BOOLEAN retCode = DIC_SUCCESS;
	CRYPT_KEYSET cryptKeyset = CRYPT_UNUSED;
	CRYPT_CONTEXT privateKeyContext = CRYPT_UNUSED;
	CRYPT_CONTEXT cryptContext = CRYPT_UNUSED;
	int status = 0;

	do
	{
		if (NULL == keyFile)
		{
			retCode = DIC_ERROR;
			break;
		}

		//status = cryptCreateContext(&cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
		//if (cryptStatusError(status))
		//{
		//	retCode = DIC_ERROR;
		//	break;
		//}
		///*cryptSetAttributeString(cryptContext, CRYPT_CTXINFO_KEYING_SALT, salt,
		//	saltLength);*/
		//cryptSetAttributeString(cryptContext, CRYPT_CTXINFO_KEYING_VALUE, "This is a secret key", 20 );

		status = cryptCreateContext(&privateKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		status = cryptSetAttributeString(privateKeyContext, CRYPT_CTXINFO_LABEL, "troioimetqua", strlen("troioimetqua"));
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		/*status = cryptSetAttributeString(privateKeyContext, CRYPT_CTXINFO_KEYING_VALUE, "1234567", 7 );
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}*/

		/*status = cryptSetAttribute(privateKeyContext, CRYPT_CTXINFO_KEYSIZE, 2048 / 8);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}*/

		status = cryptGenerateKey(privateKeyContext);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		/*status = cryptSetAttribute(privateKeyContext, CRYPT_KEYID_NAME, "anhma.test.pgp", strlen("anhma.test.pgp"));
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}*/

		status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyFile, CRYPT_KEYOPT_CREATE);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		/*status = cryptAddPrivateKey(cryptKeyset, privateKeyContext, "1234567");
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}*/

		status = cryptAddPublicKey(cryptKeyset, privateKeyContext);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		/*char* encryptedKey;
		int encryptedKeyLength = 0;
		int encryptedKeyMaxLength = 0;
		cryptExportKey(NULL, 0, &encryptedKeyMaxLength, privateKeyContext, cryptContext);
		encryptedKey = (char*)malloc(encryptedKeyMaxLength);
		memset(encryptedKey, 0, encryptedKeyMaxLength);
		cryptExportKey(encryptedKey, encryptedKeyMaxLength, &encryptedKeyLength, privateKeyContext, cryptContext);
		free(encryptedKey);*/

	} while (FALSE);

	cryptKeysetClose(cryptKeyset);
	cryptDestroyContext(privateKeyContext);

	return (retCode);
}

static int getPGPPublicKey(const KEYFILE_TYPE keyFileType,
	const char* keysetName
	//const C_STR keyFileTemplate,
	//const char *description
)
{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	//char fileName[BUFFER_SIZE]; memset(fileName, 0, BUFFER_SIZE);
	//int keyReadOK = TRUE;
	//BYTE certBuffer[BUFFER_SIZE]; memset(certBuffer, 0, BUFFER_SIZE);
	int length = 0;

#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[FILENAME_BUFFER_SIZE];
#endif /* UNICODE_STRINGS */
	//const C_STR keysetName = "D:\\pubring.pgp"; /*getKeyfileName(keyFileType, FALSE);*/
	int status;

	/* If this is the first file read, check that the file actually exists
	so that we can return an appropriate error message */
	if (keyFileType == KEYFILE_PGP)
	{
		if ((filePtr = fopen(convertFileName(keysetName), "rb")) == NULL)
			return(CRYPT_ERROR_FAILED);
		fclose(filePtr);
		//keyReadOK = FALSE;
	}

	/* If the caller has overridden the keyfile to use, use the caller-
	supplied name */
//	if (keyFileTemplate != NULL)
//	{
//		filenameFromTemplate(fileName, keyFileTemplate, 1);
//#ifdef UNICODE_STRINGS
//		mbstowcs(wcBuffer, fileName, strlen(fileName) + 1);
//		keysetName = wcBuffer;
//#else
//		keysetName = fileName;
//#endif /* UNICODE_STRINGS */
//	}

	//printf("Testing %s public key read...\n", description);

	/* Open the keyset */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
		keysetName, CRYPT_KEYOPT_READONLY);
	if (cryptStatusError(status))
	{
		/*printf("cryptKeysetOpen() failed with error code %d, line %d.\n",
			status, __LINE__);*/
		return(FALSE);
	}

	/* Get the key.  The read of the special-case PGP keyring tests the
	ability to handle over-long key packet groups so this should return
	a not-found error due to the packets being skipped */
	status = cryptGetPublicKey(cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
		/*getKeyfileUserID(keyFileType, FALSE)*/
		"anhma.test.pgp");
	if ((keyFileType == KEYFILE_PGP_SPECIAL && \
		status != CRYPT_ERROR_NOTFOUND) || \
		(keyFileType != KEYFILE_PGP_SPECIAL && \
			cryptStatusError(status)))
	{
		/*printExtError(cryptKeyset, "cryptGetPublicKey()", status,
			__LINE__);*/
		return(FALSE);
	}

	/*status = cryptExportCert(certBuffer, BUFFER_SIZE, &length,
		CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptContext);
	if (cryptStatusError(status))
	{
		return(FALSE);
	}*/

	cryptDestroyContext(cryptContext);

	/* Close the keyset */
	status = cryptKeysetClose(cryptKeyset);
	if (cryptStatusError(status))
	{
		/*printf("cryptKeysetClose() failed with error code %d, line %d.\n",
			status, __LINE__);*/
		return(FALSE);
	}

	/*printf("Read of public key from %s keyring succeeded.\n\n",
		description);*/
	return(TRUE);
}

int getPGPPrivateKey(const KEYFILE_TYPE keyFileType)
{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const C_STR keysetName = DIC_PGPKEYFILE; /*getKeyfileName(keyFileType, TRUE);*/
	const C_STR password = ""; /*getKeyfilePassword(keyFileType);*/
	int status;

	/* Open the keyset */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
		keysetName, CRYPT_KEYOPT_READONLY);
	if (cryptStatusError(status))
	{
		/*printf("cryptKeysetOpen() failed with error code %d, line %d.\n",
			status, __LINE__);*/
		return(FALSE);
	}

	/* Get the key.  First we try it without a password, if that fails we
	retry it with the password - this tests a lot of the private-key get
	functionality including things like key cacheing */
	status = cryptGetPrivateKey(cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
		getKeyfileUserID(keyFileType, TRUE), NULL);
	if (status == CRYPT_ERROR_WRONGKEY)
	{
		/* We need a password for this private key, get it from the user and
		get the key again */
		status = cryptGetPrivateKey(cryptKeyset, &cryptContext,
			CRYPT_KEYID_NAME,
			getKeyfileUserID(keyFileType, TRUE),
			password);
	}
	if (cryptStatusError(status))
	{
		/*printExtError(cryptKeyset, "cryptGetPrivateKey()", status,
			__LINE__);*/
		return(FALSE);
	}

	/* Make sure that we can use the key that we've read.  We can only do this
	with PGP 2.x keys, OpenPGP's peculiar multi-keys identify two (or more)
	keys with the same label and we can't specify (at this level) which
	key we want to use (the enveloping code can be more specific and so
	doesn't run into this problem) */
	if (keyFileType == KEYFILE_PGP)
	{
		int value;

		status = cryptGetAttribute(cryptContext, CRYPT_CTXINFO_ALGO,
			&value);
		if (cryptStatusOK(status))
		{
			status = testCrypt(cryptContext, cryptContext, value, NULL,
				FALSE, FALSE);
		}
		if (cryptStatusError(status))
			return(FALSE);
	}
	cryptDestroyContext(cryptContext);

	/* Close the keyset */
	status = cryptKeysetClose(cryptKeyset);
	if (cryptStatusError(status))
	{
		printf("cryptKeysetClose() failed with error code %d, line %d.\n",
			status, __LINE__);
		return(FALSE);
	}

	/* The public and private key reads worked, remember this for later when
	we use the keys in other tests */
	//keyReadOK = TRUE;

	return(TRUE);
}

int createDeviceSession(CRYPT_DEVICE *userDevice,
	const char *devicePassword)
{
	CRYPT_DEVICE cryptDevice;
	int status;
	/* Clear the return value */
	*userDevice = -1;
	/* Open a session with the device */
	status = cryptDeviceOpen(&cryptDevice, CRYPT_UNUSED,
		CRYPT_DEVICE_PKCS11, "[Autodetect]");
	if (cryptStatusError(status))
		return(status);
	/* Log on to the device */
	status = cryptSetAttributeString(cryptDevice,
		CRYPT_DEVINFO_AUTHENT_USER, devicePassword,
		strlen(devicePassword));
	if (cryptStatusError(status))
	{
		cryptDeviceClose(cryptDevice);
		return(status);
	}
	/* Return the device object to the caller */
	*userDevice = cryptDevice;
	return(CRYPT_OK);
}

int encryptMessage(const void *inData, const int inDataLength,
	void *outData, const int outDataMaxLength,
	int *outDataLength, const char *pubKeysetName,
	const char *recipientName,
	const CRYPT_FORMAT_TYPE formatType)
{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	int bytesCopied, status;
	/* Clear the return value */
	*outDataLength = 0;
	/* Create an envelope to wrap the data */
	status = cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED,
		formatType);
	if (cryptStatusError(status))
		return(status);
	status = cryptSetAttribute(cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
		inDataLength);
	if (cryptStatusError(status))
	{
		cryptDestroyEnvelope(cryptEnvelope);
		return(status);
	}
	/* Add the public-key keyset and recipient name to the envelope */
	status = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
		CRYPT_KEYSET_ODBC,
		/*CRYPT_KEYSET_FILE,*/
		pubKeysetName, CRYPT_KEYOPT_READONLY);
	if (cryptStatusOK(status))
	{
		status = cryptSetAttribute(cryptEnvelope,
			CRYPT_ENVINFO_KEYSET_ENCRYPT, cryptKeyset);
		cryptKeysetClose(cryptKeyset);
	}
	if (cryptStatusOK(status))
	{
		status = cryptSetAttributeString(cryptEnvelope,
			CRYPT_ENVINFO_RECIPIENT, recipientName,
			strlen(recipientName));
	}
	if (cryptStatusError(status))
	{
		cryptDestroyEnvelope(cryptEnvelope);
		return(status);
	}
	/* Push the data to be encrypted into the envelope */
	status = cryptPushData(cryptEnvelope, inData, inDataLength,
		&bytesCopied);
	if (cryptStatusOK(status))
	{
		if (bytesCopied != inDataLength)
			status = -1; /* Not all data was processed */
		else
			status = cryptFlushData(cryptEnvelope);
	}
	if (cryptStatusError(status))
	{
		cryptDestroyEnvelope(cryptEnvelope);
		return(status);
	}
	/* Pop the encrypted result back out */
	status = cryptPopData(cryptEnvelope, outData, outDataMaxLength,
		outDataLength);
	cryptDestroyEnvelope(cryptEnvelope);

	return(status);
}

int decryptMessage(const void *inData, const int inDataLength,
	void *outData, const int outDataMaxLength,
	int *outDataLength, const char *privKeysetName,
	const char *privKeyPassword)
{
	CRYPT_ENVELOPE cryptEnvelope;
	int bytesCopied, status;
	/* Clear the return value */
	*outDataLength = 0;
	/* Create an envelope to unwrap the data */
	status = cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED,
		CRYPT_FORMAT_AUTO);
	if (cryptStatusError(status))
		return(status);
	/* Add the decryption keyset to the envelope. If a filename is
	given then we assume that it's a file keyset, otherwise it's a
	device */
	if (privKeysetName != NULL)
	{
		CRYPT_KEYSET cryptKeyset;
		/* Add the decryption keyset to the envelope */
		status = cryptKeysetOpen(&cryptKeyset,
			CRYPT_UNUSED,
			CRYPT_KEYSET_FILE,
			/*CRYPT_KEYSET_ODBC,*/
			privKeysetName,
			CRYPT_KEYOPT_READONLY);
		if (cryptStatusOK(status))
		{
			status = cryptSetAttribute(cryptEnvelope,
				CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset);
			cryptKeysetClose(cryptKeyset);
		}
	}
	else
	{
		CRYPT_DEVICE cryptDevice;
		/* Add the decryption device to the envelope */
		status = createDeviceSession(&cryptDevice, privKeyPassword);
		if (cryptStatusOK(status))
		{
			status = cryptSetAttribute(cryptEnvelope,
				CRYPT_ENVINFO_KEYSET_DECRYPT, cryptDevice);
			cryptDeviceClose(cryptDevice);
		}
	}

	if (cryptStatusError(status))
	{
		cryptDestroyEnvelope(cryptEnvelope);
		return(status);
	}
	/* Push the encrypted data into the envelope */
	status = cryptPushData(cryptEnvelope, inData, inDataLength,
		&bytesCopied);
	if (cryptStatusOK(status) && bytesCopied != inDataLength)
		status = -1; /* Not all data was processed */
	if (status == CRYPT_ENVELOPE_RESOURCE)
	{
		int cryptEnvInfo;
		/* Find out what's required in order to continue */
		status = cryptGetAttribute(cryptEnvelope,
			CRYPT_ATTRIBUTE_CURRENT, &cryptEnvInfo);
		if (cryptStatusOK(status))
		{
			switch (cryptEnvInfo)
			{
			case CRYPT_ATTRIBUTE_NONE:
				/* We're using a device for decryption, there's nothing
				left to do since decryption has been automatically
				handled by the device */
				break;
			case CRYPT_ENVINFO_PRIVATEKEY:
				/* We're using a keyset for decryption, we need to
				supply the password to decrypt the private key */
				status = cryptSetAttributeString(cryptEnvelope,
					CRYPT_ENVINFO_PASSWORD, privKeyPassword,
					strlen(privKeyPassword));
				break;
			default:
				/* Something unexpected happened */
				status = -1;
			}
		}
	}
	if (cryptStatusOK(status))
		status = cryptFlushData(cryptEnvelope);
	if (cryptStatusError(status))
	{
		cryptDestroyEnvelope(cryptEnvelope);
		return(status);
	}
	/* Pop the decrypted result back out */
	status = cryptPopData(cryptEnvelope, outData, outDataMaxLength,
		outDataLength);
	cryptDestroyEnvelope(cryptEnvelope);
	return(status);
}

BOOLEAN testUsers(void)
{
	char encryptedBuf[DIC_BUFFSZ]; memset(encryptedBuf, 0, DIC_BUFFSZ);
	char fileContentBuf[DIC_BUFFSZ]; memset(fileContentBuf, 0, DIC_BUFFSZ);
	char decryptedBuf[DIC_BUFFSZ]; memset(decryptedBuf, 0, DIC_BUFFSZ);
	int decryptedBufLen = 0;
	int encryptedBufLen = 0;
	FILE* fp = NULL;
	BOOLEAN retCode = DIC_SUCCESS;
	int status = 0;

	do
	{
		cryptInit();

		/*CRYPT_CERTIFICATE cryptCert;
		convertPGPtoCert("D:/client.pub", "test.pgp", &cryptCert, NULL);*/

		/*status = dicGenerateKey(DIC_PGPKEYFILE);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}*/

		// Reading data from file to buffer
		fp = fopen("D:/test_local_302.x12", "r");
		if (NULL == fp)
		{
			retCode = DIC_ERROR;
			break;
		}
		fread(fileContentBuf, sizeof(char), DIC_BUFFSZ, fp);
		fclose(fp);
		fp = NULL;

		// Generate key pair
		status = generateKey(
			"anhma7", // keyOwnerName
			"anhma7@dicetral.com", // keyOwnerEmail
			"testkeys", // keyOwnerDSNName
			"test pgp authen 7", // keyLabel
			DIC_PGPKEYFILE, // privateKetsetName
			"123456", // privateKetPassword
			"testkeys"); // pubKetsetName
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		// Encrypting buffer block using CRYPT_FORMAT_PGP format type
		status = encryptMessage(fileContentBuf,
			strlen(fileContentBuf) + 1,
			encryptedBuf,
			DIC_BUFFSZ,
			&encryptedBufLen,
			"testkeys",
			//"D:/troioimetqua.pgp",
			"anhma7@dicetral.com",
			CRYPT_FORMAT_PGP);
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		// Try to write the encrypted data into the file
		fp = fopen("D:/enc.message", "wb");
		if (NULL == fp)
		{
			retCode = DIC_ERROR;
			break;
		}
		fwrite(encryptedBuf, sizeof(char), encryptedBufLen, fp);
		fclose(fp);
		fp = NULL;

		// Try to decrypt the encrypted data
		status = decryptMessage(encryptedBuf, encryptedBufLen,
			decryptedBuf, DIC_BUFFSZ,
			&decryptedBufLen,
			DIC_PGPKEYFILE,
			//"testkeys",
			"123456");
		if (cryptStatusError(status))
		{
			retCode = DIC_ERROR;
			break;
		}

		//// Try to write the decrypted data into the file
		fp = fopen("D:/dec.message", "wb");
		if (NULL == fp)
		{
			retCode = DIC_ERROR;
			break;
		}
		fwrite(decryptedBuf, sizeof(char), decryptedBufLen, fp);
		fclose(fp);
		fp = NULL;

	} while (FALSE);

	/*FILE *file;
	char buffer[9999]; memset(buffer, 0, 9999);
	int p;
	int bytesCopied;
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_ENVELOPE cryptEnvelope2;

	file = fopen("D:/test_local_302.x12", "r");
	if (!file)return 1;
	p = fread(buffer, 1, 9999, file);
	if (!p) return 1;
	fclose(file);

	cryptInit();
	cryptCreateEnvelope(&cryptEnvelope, CRYPT_UNUSED, CRYPT_FORMAT_CMS);
	cryptSetAttributeString(cryptEnvelope, CRYPT_ENVINFO_PASSWORD, "password", 8);
	cryptPushData(cryptEnvelope, buffer, p, &bytesCopied);
	cryptFlushData(cryptEnvelope);
	cryptPopData(cryptEnvelope, buffer, 10000, &bytesCopied);
	cryptDestroyEnvelope(cryptEnvelope);

	file = fopen("D:/envelopedfile", "wb");
	fwrite(buffer, 1, bytesCopied, file);
	fclose(file);

	cryptCreateEnvelope(&cryptEnvelope2, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
	cryptPushData(cryptEnvelope2, buffer, bytesCopied, &bytesCopied);
	cryptSetAttributeString(cryptEnvelope2, CRYPT_ENVINFO_PASSWORD, "password", 8);
	cryptFlushData(cryptEnvelope2);
	cryptPopData(cryptEnvelope2, buffer, 10000, &bytesCopied);
	cryptDestroyEnvelope(cryptEnvelope2);

	file = fopen("D:/denvelopedfile", "wb");
	fwrite(buffer, bytesCopied, 1, file);
	fclose(file);*/

	return(retCode);
}
/* DICENTRAL CODE BLOCK */

/****************************************************************************
*																			*
*							Test Memory Fault-injection						*
*																			*
****************************************************************************/

/* Test error-handling code paths by forcing memory-allocation faults at
   every location in which cryptlib allocates memory.  Note that this test
   can only be run if all of the cryptlib self-tests complete successfully,
   since it injects memory faults until the self-tests report success */

   /*#define TEST_MEMFAULT	/* Undefine to perform memory-fault tests */

#ifdef TEST_MEMFAULT

#if !defined( TEST_SELFTEST ) || !defined( TEST_CERT ) || \
	!defined( TEST_HIGHLEVEL )
#error Need to enable all tests for fault-allocation test.
#endif /* Defines to indicate that all tests are enabled */

BOOLEAN testInit(void)
{
	int status;

	status = cryptInit();
	return(cryptStatusError(status) ? FALSE : TRUE);
}

#define FAULT_STARTFUNCTION	0
#define FAULT_STARTINDEX	0

typedef int(*FUNCTION_PTR)(void);
typedef struct {
	FUNCTION_PTR function;
	const char *functionName;
} FUNCTION_TBL;

#define MK_FN( function )	{ function, #function }

static const FUNCTION_TBL functionTbl[] = {
	MK_FN(testInit),
	MK_FN(testSelfTest),
	MK_FN(testLowLevel),
	MK_FN(testRandom),
	MK_FN(testConfig),
	MK_FN(testDevice),
	MK_FN(testMidLevel),
	MK_FN(testCert),
	MK_FN(testKeysetFile),
	MK_FN(testKeysetDatabase),
	MK_FN(testCertMgmt),
	MK_FN(testHighLevel),
	MK_FN(testEnveloping),
	MK_FN(testSessions),
	MK_FN{ NULL )
	};

static void testMemFault(void)
	{
	int functionIndex;

	/* Since we don't want to have tons of diagnostic output interspersed
	   with the mem-fault output, we redirect the diagnostic output to
	   /dev/null */
	outputStream = fopen("nul:", "w");
	assert(outputStream != NULL);

	puts("Testing memory fault injection...");
	for (functionIndex = FAULT_STARTFUNCTION;
		 functionTbl[functionIndex].function != NULL;
		 functionIndex++)
		{
		int memFaultIndex;

		for (memFaultIndex = FAULT_STARTINDEX; memFaultIndex < 10000;
			 memFaultIndex++)
			{
			int status;

			/* If we're testing something other than the cryptInit()
			   functionality then we need to initialise cryptlib first */
			if (functionIndex != 0)
				{
				/* Since we've already tested the init functionality, we
				   don't want to fault the init any more */
				cryptSetMemFaultCount(10000);
				status = cryptInit();
				assert(cryptStatusOK(status));
				}

			/* Tell the debug-allocator to return an out-of-memory condition
			   after the given number of allocations */
			printf("%s: %d.\r", functionTbl[functionIndex].functionName,
					memFaultIndex);
			cryptSetMemFaultCount(memFaultIndex);

			/* Call the test function, with a memory fault at the given
			   memory allocation number */
			status = functionTbl[functionIndex].function();
			if (status != TRUE)
				{
				if (functionIndex != 0)
					cryptEnd();
				continue;
				}
			cryptEnd();
			break;
			}
		assert(memFaultIndex < 10000);
		putchar('\n');
		}
	}
#endif /* TEST_MEMFAULT	*/
#endif /* TEST_USER */
