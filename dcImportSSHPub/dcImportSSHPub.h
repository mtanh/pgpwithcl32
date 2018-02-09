#pragma once


#include <stdio.h>
#include <assert.h>
#include <Rpc.h>

#ifdef __cplusplus
	#define SSHPUB_DECL extern "C" __declspec(dllexport)
#else
	#define SSHPUB_DECL __declspec(dllexport)
#endif

#define WIN32_LEAN_AND_MEAN 
#define NOCRYPT

#define	SQLAPI_DBTYPE_STRING_NOT_SPECIFIED		"Not specified"
#define	SQLAPI_DBTYPE_STRING_ODBC				"ODBC"
#define	SQLAPI_DBTYPE_STRING_ORACLE				"ORACLE"
#define	SQLAPI_DBTYPE_STRING_SQLSERVER			"SQLSERVER"
#define	SQLAPI_DBTYPE_STRING_INTERBASE			"INTERBASE"
#define	SQLAPI_DBTYPE_STRING_SQLBASE			"SQLBASE"
#define	SQLAPI_DBTYPE_STRING_DB2				"DB2"
#define	SQLAPI_DBTYPE_STRING_INFORMIX			"INFORMIX"
#define	SQLAPI_DBTYPE_STRING_SYBASE				"SYBASE"
#define	SQLAPI_DBTYPE_STRING_MYSQL				"MYSQL"
#define	SQLAPI_DBTYPE_STRING_POSTGRESQL			"POSTGRESQL"
#define	SQLAPI_DBTYPE_STRING_SQLITE				"SQLITE"

#define IN
#define OUT
#define CERT_STATUS_ACTIVE 1
#define CERT_STATUS_INACTIVE 0
const char* CONFIGURATION_FILE = "dcCertsLib.cfg";

typedef enum
{
	ERRCODE_UNKNOWN = 0,
	ERRCODE_SSHCONVERT_FAILED,
	ERRCODE_ADDKEY_FAILED,
	ERRCODE_READ_CONF,
	ERRCODE_INSERT_DB,
	ERRCODE_NULL_INPUT,
	ERRCODE_CRYPT_DESTROY_CERT_FAILED,
	ERRCODE_CRYPT_END_FAILED,
} SSHPUB_ERRCODE;

typedef struct
{
	char dbConnectionString[1024];
} SSHPUB_CONFIGURATION, *PSSHPUB_CONFIGURATION;

SSHPUB_DECL int utilImportPublicKey(
	IN long certSetId,
	IN char* sshPubFilePath,
	IN char* keyAlias,
	OUT char* erroMsg,
	IN int errorMsgLen);

extern char* dbConnectionStringPtr;
extern char* caFilePathPtr;