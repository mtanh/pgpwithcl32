#include <cryptlib.h>
#include <SQLAPI.h>
#include "dcImportSSHPub.h"
#include "dcLogNew.h"

#define BUFSZ 256
#define MAXBUFSZ 1024

char* dbConnectionStringPtr = nullptr;
char* caFilePathPtr = nullptr;
static char dbConnectionString[MAXBUFSZ];
static char caFilePath[MAXBUFSZ];
static bool dcLogNewInit = false;

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

/* Function Prototype */
static int readConfig(PSSHPUB_CONFIGURATION pSshPubConfig, char* errMsg, int errMsgLen);
static int getFullPathLib(char* strPath, char* strFileName, char* strFullPath, int nLength);
static int insertSshCertToCertMapping(IN const char* keyAlias, IN long certSetId, IN CRYPT_CERTIFICATE certificate);
static bool convertBinaryToHexString(char* binary, int srcLen, char* outHexString, int outHexLen);
static void getTimeString(const time_t theTime, char* result, int resultLen);
static void scanForQuoteCharacter(char* str, int strLen);
static int nonQueryCommand(const char* connectionString, const char* query, char* errMsg, int errMsgLen);
static void	dbConnect(SAConnection* pDbCon, const char* connectionString, char* errMsg, int errMsgLen);
static void	getConnectionStringElement(char* dsn, char* element, char* ret, const int retLen);
static void	cleanString(char* readBuf);
static int getDatabaseTypeFromString(char* _dbTypeName);
static char* makeGuidString(char* uniqueId, int uniqueIdLen);
static char* convertHexToChar(char* hex, char* ascii, int len);
static void convertToDsnForKeySet(const char* conSrt, char* dsnForKeySet, int dsnForKeySetLen);

/* Function Declaration */
SSHPUB_DECL int utilImportPublicKey(
	IN long certSetId,
	IN char* sshPubFilePath,
	IN char* keyAlias,
	OUT char* erroMsg,
	IN int errorMsgLen)
{
	int ret = CRYPT_OK;
	do
	{
		if (nullptr == sshPubFilePath ||
			nullptr == erroMsg)
		{
			ret = ERRCODE_NULL_INPUT;
			break;
		}

		// Init lognew
		if (false == dcLogNewInit)
		{
			char* theString = "A"; // Enable ALL log bit
			unsigned int theLogMask = LogMaskStr2Mask(theString);
			if (theLogMask)
			{
				char* defaultLogDir = "C:\\sshimportpub.logs\\";
				char* logDir = defaultLogDir;

				CreateDirectory(logDir, NULL); // force creating log folder
				assert(logDir[0] != 0);
				assert(logDir[strlen(logDir) - 1] == '/');

				InitLogEx(logDir,
					"DIC.SSHPUB.",
					LOG_OPTION_USE_SINGLE_FILE | LOG_OPTION_SWITCH_FILES | LOG_OPTION_LOG_THREAD_ID | LOG_OPTION_AUTO_PURGE,
					DEFAULT_NKEEP);

				SetLogMask(theLogMask);
				SetAutoPurgePeriod(200); // 200 days
			}

			dcLogNewInit = true;
		}

		LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);

		int res = CRYPT_OK;

		res = cryptInit();
		if (cryptStatusError(res))
		{
			puts("Couldn't reload cryptlib configuration.");
			LogPrintf(LOG_INFO, "Couldn't reload cryptlib configuration.");
			ret = CRYPT_ERROR_FAILED;
			break;
		}

		/*char keyAlias[37] = { 0 };
		makeGuidString(keyAlias, sizeof(keyAlias));*/
		//LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);

		// get connection string from config file
		SSHPUB_CONFIGURATION sshPubConfig;
		char errMsg[1024] = { 0 };
		int errMsgLen = 1024;
		res = readConfig(&sshPubConfig, errMsg, errMsgLen);
		if (res != CRYPT_OK)
		{
			strcpy_s(erroMsg, errorMsgLen, "Read configuration file failed.");
			ret = ERRCODE_READ_CONF;
			break;
		}
		LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);

		CRYPT_CERTIFICATE cryptCert;
		LogPrintf(LOG_INFO, "sshPubFilePath: %s\n", sshPubFilePath);
		LogPrintf(LOG_INFO, "keyAlias: %s\n", keyAlias);
		assert(caFilePathPtr != nullptr);
		if (nullptr == caFilePathPtr)
		{
			ret = ERRCODE_NULL_INPUT;
			LogPrintf(LOG_INFO, "ERRCODE_NULL_INPUT\n");
			break;
		}

		dicUserDataBundle userData;
		userData.m_caFilePath = caFilePathPtr;
		res = convertSSHtoCert(sshPubFilePath, keyAlias, &cryptCert, &userData);
		if (res != CRYPT_OK)
		{
			strcpy_s(erroMsg, errorMsgLen, "Convert SSH public key to certificate failed.");
			ret = ERRCODE_SSHCONVERT_FAILED;
			break;
		}
		LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);



		char extractedDsn[BUFSZ];
		memset(extractedDsn, '\0', BUFSZ);

		assert(dbConnectionStringPtr != nullptr);
		if (nullptr == dbConnectionStringPtr)
		{
			ret = ERRCODE_NULL_INPUT;
			break;
		}
		convertToDsnForKeySet(dbConnectionStringPtr, extractedDsn, BUFSZ);
		LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);

		res = insertSshCertToCertMapping(keyAlias, certSetId, cryptCert);
		if (res != CRYPT_OK)
		{
			strcpy_s(erroMsg, errMsgLen, "Add key to dicentral database failed.");
			ret = ERRCODE_INSERT_DB;
			break;
		}

		LogPrintf(LOG_INFO, "extractedDsn: %s", extractedDsn);
		LogPrintf(LOG_INFO, "cryptCert: %d", cryptCert);
		res = addKeyToDatabase(extractedDsn, cryptCert);
		LogPrintf(LOG_INFO, "addKeyToDatabase --- res: %d", res);
		if (res != CRYPT_OK)
		{
			strcpy_s(erroMsg, errMsgLen, "Add key to cryptlib database failed.");
			ret = ERRCODE_ADDKEY_FAILED;
			break;
		}
		LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);

		//LogPrintf(LOG_INFO, "%s %d %d", __FILE__, __LINE__, ret);

		/*res = cryptDestroyCert(cryptCert);
		if (res != CRYPT_OK)
		{
			LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);
			ret = ERRCODE_CRYPT_DESTROY_CERT_FAILED;
			break;
		}*/

		res = cryptEnd();
		if (res != CRYPT_OK)
		{
			LogPrintf(LOG_INFO, "%s %d", __FILE__, __LINE__);
			ret = ERRCODE_CRYPT_END_FAILED;
			break;
		}

	} while (false);

	return (ret);
}

int readConfig(PSSHPUB_CONFIGURATION pSshPubConfig, char* errMsg, int errMsgLen)
{
	//char* func = "ReadConfig";
	FILE* fp = (FILE*)0;
	char* configFileName = "dcCertsLib.cfg";
	char configFilePath[MAX_PATH] = { 0 };
	char configFileSpec[MAX_PATH] = { 0 };
	char readBuf[1024] = { 0 };
	char* value = NULL;
	char* keyword = (char*)0;

	::GetModuleFileNameA((HINSTANCE)&__ImageBase, configFilePath, sizeof(configFilePath));
	for (int i = strlen(configFilePath) - 1; i >= 0; i--)
	{
		if (configFilePath[i] == '\\')
		{
			configFilePath[i + 1] = 0;
			break;
		}
	}

	getFullPathLib(configFilePath, configFileName, configFileSpec, sizeof(configFileSpec));

	if (fopen_s(&fp, configFileSpec, "r") != 0)
	{
		sprintf_s(errMsg, errMsgLen, "Cannot open config file[%s]", configFileSpec);
		return 0;
	}

	dbConnectionStringPtr = dbConnectionString;
	caFilePathPtr = caFilePath;

	while (fgets(readBuf, sizeof(readBuf), fp))
	{
		// ---------------------------------------------------------------------
		//	Skip lines which are comments (begin with '#') and lines which do not have a keyword and value pair
		// ---------------------------------------------------------------------
		if (readBuf[0] == '#')
			continue;

		for (int i = (int)strlen(readBuf) - 1; i >= 0; i--)
		{
			if (readBuf[i] == '\n' || readBuf[i] == '\r' || readBuf[i] == ' ' || readBuf[i] == 0x25 || readBuf[i] == 0x15)
			{
				readBuf[i] = 0;
			}
			else
			{
				break;
			}
		}

		keyword = readBuf;
		value = strchr(readBuf, '=');
		if (value == (char*)0)
		{
			continue; // Skip blank line in config file
		}
		else
		{
			value[0] = '\0';
			value++;
		}

		if (strlen(value) == 0)
		{
			//sprintf_s(errMsg, errMsgLen, "%s: CONFIG ERROR: no value for keyword [%s]\n", func, keyword);
			fclose(fp);
			return 0;
		}
		else if (!_stricmp(keyword, "dbConnectionString"))
		{
			sprintf_s(dbConnectionStringPtr, MAXBUFSZ, "%s", value);
		}
		/*else if (!_stricmp(keyword, "caFilePath"))
		{
			sprintf_s(caFilePathPtr, MAXBUFSZ, "%s", value);
		}*/

		// determine the path of ca.p15
		getFullPathLib(configFilePath, "ca.p15", caFilePathPtr, MAXBUFSZ);
	}

	fclose(fp);
	return (CRYPT_OK);
}

int getFullPathLib(char* strPath, char* strFileName, char* strFullPath, int nLength)
{
	char* func = "getFullPathLib";
	int nPathSize = strlen(strPath);
	int nFileNameSize = strlen(strFileName);
	if (strPath[nPathSize - 1] == '\\')
	{
		if (nLength <= nPathSize + nFileNameSize)
		{
			return 0;
		}
		sprintf_s(strFullPath, nPathSize + 1, "%s", strPath);
		sprintf_s(strFullPath + nPathSize, nFileNameSize + 1, "%s", strFileName);
	}
	else
	{
		if (nLength <= nPathSize + nFileNameSize + 1)
		{
			return 0;
		}
		sprintf_s(strFullPath, nPathSize + 1, "%s", strPath);
		strFullPath[nPathSize] = '\\';
		sprintf_s(strFullPath + nPathSize + 1, nFileNameSize + 1, "%s", strFileName);
	}
	return (CRYPT_OK);
}

int insertSshCertToCertMapping(IN const char* keyAlias, IN long certSetId, IN CRYPT_CERTIFICATE certificate)
{
	static char* func = "insertToCertMapping";
	char query[2048];
	int rc = 0;
	int length = 0;
	char errMsg[1024] = { 0 };
	int errMsgLen = 1024;

	LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);

	rc = cryptSetAttribute(certificate, CRYPT_ATTRIBUTE_CURRENT, CRYPT_CERTINFO_SUBJECTNAME);

	char CN[MAXBUFSZ]; memset(CN, '\0', MAXBUFSZ);
	rc = cryptGetAttributeString(certificate, CRYPT_CERTINFO_COMMONNAME, CN, &length);
	if (rc != CRYPT_OK)
	{
		LogPrintf(LOG_INFO, "insertSshCertToCertMapping: Could not get CRYPT_CERTINFO_COMMONNAME from cert");
		return (CRYPT_ERROR_FAILED);
	}

	time_t validFrom;
	rc = cryptGetAttributeString(certificate, CRYPT_CERTINFO_VALIDFROM, &validFrom, &length);
	if (rc != CRYPT_OK)
	{
		LogPrintf(LOG_INFO, "insertSshCertToCertMapping: Could not get CRYPT_CERTINFO_VALIDFROM from cert");
		return (CRYPT_ERROR_FAILED);
	}

	time_t validTo;
	rc = cryptGetAttributeString(certificate, CRYPT_CERTINFO_VALIDTO, &validTo, &length);
	if (rc != CRYPT_OK)
	{
		LogPrintf(LOG_INFO, "insertSshCertToCertMapping: Could not get CRYPT_CERTINFO_VALIDTO from cert");
		return (CRYPT_ERROR_FAILED);
	}

	char validToStr[256];
	char validFromStr[256];
	getTimeString(validTo, validToStr, sizeof(validToStr));
	getTimeString(validFrom, validFromStr, sizeof(validFromStr));

	char serialNum[MAXBUFSZ]; memset(serialNum, '\0', MAXBUFSZ);
	rc = cryptGetAttributeString(certificate, CRYPT_CERTINFO_SERIALNUMBER, &serialNum, &length);
	if (rc != CRYPT_OK)
	{
		LogPrintf(LOG_INFO, "insertSshCertToCertMapping: Could not get CRYPT_CERTINFO_SERIALNUMBER from cert");
		return (CRYPT_ERROR_FAILED);
	}

	char serialNumBuf[MAXBUFSZ]; memset(serialNumBuf, '\0', MAXBUFSZ);
	(void)convertHexToChar(serialNum, serialNumBuf, 8);
	char formatedSerialNumber[MAXBUFSZ]; memset(formatedSerialNumber, '\0', MAXBUFSZ);
	strcpy(formatedSerialNumber, "0x");
	strcat(formatedSerialNumber, serialNumBuf);
	LogPrintf(LOG_INFO, "insertSshCertToCertMapping: serialNum: %s\n", formatedSerialNumber);

	sprintf_s(query, sizeof(query),
		"INSERT INTO CertMapping ([Alias], \
			[CN], \
			[Email], \
			[ValidTo], \
			[ValidFrom], \
			[CNOfIssuer], \
			[SerialNumber], \
			[CertSetID], \
			[Status]) \
			VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', %ld, %d)",
		keyAlias,
		CN,
		"admin@dicetral.com",
		validToStr,
		validFromStr,
		CN,
		formatedSerialNumber,
		certSetId,
		CERT_STATUS_ACTIVE);

	LogPrintf(LOG_INFO, "%s", query);

	if ((rc = nonQueryCommand(dbConnectionStringPtr, query, errMsg, errMsgLen)) != CRYPT_OK)
	{
		LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);
		return (CRYPT_ERROR_FAILED);
	}

	LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);
	return (CRYPT_OK);
}

bool convertBinaryToHexString(char* binary, int srcLen, char* outHexString, int outHexLen)
{
	static char hexChars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	int currentPos = 0;
	if (outHexLen < 2 * srcLen + 1) {
		return false;
	}
	for (int i = 0; i < srcLen; i++) {
		unsigned char a = binary[i];
		outHexString[currentPos++] = hexChars[a >> 4];
		outHexString[currentPos++] = hexChars[a & 0xf];
	}
	outHexString[currentPos] = '\0';
	return true;
}

void getTimeString(const time_t theTime, char* result, int resultLen)
{
	static char*	func = "getTimeString";
	static char		timeString[64];
	struct tm		timeinfo;

	gmtime_s(&timeinfo, &theTime);
	strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", &timeinfo);
	timeString[strlen(timeString)] = '\0';
	strcpy_s(result, resultLen, timeString);
}

void scanForQuoteCharacter(char* str, int strLen)
{
	char tmp[1024] = { 0 };
	for (int i = 0, j = 0; i < strlen(str); i++, j++)
	{
		if (str[i] == '\'')
		{
			// Add double ' character
			tmp[j++] = '\'';
			tmp[j] = '\'';
		}
		else
		{
			tmp[j] = str[i];
		}
	}
	if (strlen(str) != strlen(tmp))
	{
		// Copy tmp back to str
		sprintf_s(str, strLen, "%s", tmp);
	}
}

int nonQueryCommand(const char* connectionString, const char* query, char* errMsg, int errMsgLen)
{
	static char*	func = "nonQueryCommand()";
	SAConnection	con, *pDbCon = &con;		// connection object
	SACommand		cmd;					    // create command object
	int				rc = CRYPT_ERROR_FAILED;

	try {
		LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);

		assert(connectionString != nullptr || connectionString[0] != '\0');
		assert(query != nullptr || query[0] != '\0');

		LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);

		dbConnect(pDbCon, dbConnectionStringPtr, errMsg, errMsgLen);
		cmd.setConnection(pDbCon);
		cmd.setCommandText(query);
		cmd.Execute();
		pDbCon->Commit();

		LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);
		rc = CRYPT_OK;
	}
	catch (SAException &x)
	{
		try
		{
			LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);
			pDbCon->Rollback();
		}
		catch (SAException &ex)
		{
			LogPrintf(LOG_INFO, "%s: %s", __FUNCTION__, (const char*)ex.ErrText());
		}
	}

	LogPrintf(LOG_INFO, "%s %d", __FUNCTION__, __LINE__);
	return (rc);
}

void dbConnect(SAConnection* pDbCon, const char* connectionString, char* errMsg, int errMsgLen)
{
	static char*	func = "dbConnect()";
	char*			p = (char*)0;
	char*			pDbDsn = (char*)0;
	SAClient_t		dbType = SA_Client_NotSpecified;
	char			dbTypeString[128], dbDsn[128], dbUid[128], dbPwd[128];

	getConnectionStringElement((char*)connectionString, "dbType=", dbTypeString, sizeof(dbDsn));
	getConnectionStringElement((char*)connectionString, "DSN=", dbDsn, sizeof(dbDsn));
	getConnectionStringElement((char*)connectionString, "Uid=", dbUid, sizeof(dbUid));
	getConnectionStringElement((char*)connectionString, "Pwd=", dbPwd, sizeof(dbPwd));

	dbType = (SAClient_t)getDatabaseTypeFromString(dbTypeString);
	dbType = (dbType == SA_Client_NotSpecified ? SA_SQLServer_Client : dbType);	// Default to SQLServer
	pDbDsn = (dbType == SA_ODBC_Client ? ((p = strstr(dbDsn, "@")) ? ++p : dbDsn) : dbDsn);

	try
	{
		pDbCon->setClient(dbType);
		pDbCon->Connect(pDbDsn, dbUid, dbPwd, dbType);
	}
	catch (SAException &x)
	{
		try
		{
			pDbCon->setClient((SAClient_t)SA_ODBC_Client);
			pDbCon->Connect(connectionString, "", "", SA_ODBC_Client);
		}
		catch (SAException &)
		{
			throw x;
		}
	}
}

void getConnectionStringElement(char* dsn, char* element, char* ret, const int retLen)
{
	static char* func = "getConnectionStringElement";
	char* start = (char*)0;
	char* end = (char*)0;
	char* pLoc = (char*)0;
	char dsnBuf[BUFSZ];
	char elementBuf[BUFSZ];
	ret[0] = (char)0;

	if (nullptr == dsn || dsn[0] == '\0') { return; }
	if (nullptr == element || element[0] == '\0') { return; }

	strcpy_s(dsnBuf, BUFSZ, dsn);
	strcpy_s(elementBuf, BUFSZ, element);

	(void)_strupr_s(dsnBuf, BUFSZ);
	(void)_strupr_s(elementBuf, BUFSZ);
	if (!(pLoc = strstr(dsnBuf, elementBuf)))
	{
		return;
	}

	start = dsn + (pLoc - dsnBuf + strlen(elementBuf));

	if ((end = strchr(start, ';')))
	{
		strncpy_s(ret, retLen, start, (int)(end - start));
	}
	else
	{
		strcpy_s(ret, retLen, start);
	}

	cleanString(ret);
}

void cleanString(char* readBuf)
{
	for (int i = (int)strlen(readBuf) - 1; i >= 0; i--)
	{
		if (readBuf[i] == '\n' || readBuf[i] == '\r' || readBuf[i] == ' ' || readBuf[i] == 0x25 || readBuf[i] == 0x15)
		{
			readBuf[i] = 0;
		}
		else
		{
			break;
		}
	}
}

int getDatabaseTypeFromString(char* _dbTypeName)
{
	static char*	func = "getDatabaseTypeFromString";
	char			dbTypeName[64];
	int				dbTypeNameLen = sizeof(dbTypeName);

	if (nullptr == _dbTypeName || _dbTypeName[0] == '\0')
	{
		return(SA_Client_NotSpecified);
	}
	else
	{
		strcpy_s(dbTypeName, dbTypeNameLen, _dbTypeName);
		_strupr_s(dbTypeName, dbTypeNameLen);
	}

	if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_ODBC))
		return(SA_ODBC_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_ORACLE))
		return(SA_Oracle_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_SQLSERVER))
		return(SA_SQLServer_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_INTERBASE))
		return(SA_InterBase_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_SQLBASE))
		return(SA_SQLBase_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_DB2))
		return(SA_DB2_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_INFORMIX))
		return(SA_Informix_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_SYBASE))
		return(SA_Sybase_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_MYSQL))
		return(SA_MySQL_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_POSTGRESQL))
		return(SA_PostgreSQL_Client);
	else if (strstr(dbTypeName, SQLAPI_DBTYPE_STRING_SQLITE))
		return(SA_SQLite_Client);
	else
		return(SA_Client_NotSpecified);
}

char* makeGuidString(char* uniqueId, int uniqueIdLen)
{
	static char*	func = "makeGuidString";
	if (uniqueIdLen < 37)
	{
		return uniqueId;
	}
	RPC_STATUS	rc = 0;
	char f1[8 + 1], f2[4 + 1], f3[4 + 1], f4[16 + 1], b4[4 + 1];
	GUID* pGuid = new GUID;

	// Create a new GUID
	if ((rc = UuidCreate(pGuid)) == RPC_S_OK || rc == RPC_S_UUID_LOCAL_ONLY)
	{
		//dcSprintf_s(f1, sizeof(f1), __LINE__, func, "%8.8X", pGuid->Data1);
		sprintf_s(f1, sizeof(f1), "%8.8X", pGuid->Data1);
		//dcSprintf_s(f2, sizeof(f2), __LINE__, func, "%4.4X", pGuid->Data2);
		sprintf_s(f2, sizeof(f2), "%4.4X", pGuid->Data2);
		//dcSprintf_s(f3, sizeof(f3), __LINE__, func, "%4.4X", pGuid->Data3);
		sprintf_s(f3, sizeof(f3), "%4.4X", pGuid->Data3);
		(void)convertHexToChar((char*)pGuid->Data4, f4, 8);
		f4[16] = (char)0;
		memcpy_s(b4, 4 + 1, f4, 4);
		b4[4] = (char)0;
		//dcSprintf_s(uniqueId, uniqueIdLen, __LINE__, func, "%8.8s-%4.4s-%4.4s-%4.4s-%12.12s", f1, f2, f3, b4, &f4[4]);
		sprintf_s(uniqueId, uniqueIdLen, "%8.8s-%4.4s-%4.4s-%4.4s-%12.12s", f1, f2, f3, b4, &f4[4]);
	}

	delete pGuid;
	return uniqueId;
}

char* convertHexToChar(char* hex, char* ascii, int len)
{
	int i = 0;
	int j = 0;
	int x = 0;
	int radix0 = 0x37;
	int radix1 = 0x30;

	// Translate hex to ascii
	for (x = 0; x < len; x++)
	{
		i = (unsigned int)hex[x];
		j = (i >> 4) & 0x000f;
		j = (j > 9 ? j + radix0 : j + radix1);
		*ascii++ = (unsigned char)j;
		j = i & 0x000f;
		j = (j > 9 ? j + radix0 : j + radix1);
		*ascii++ = (unsigned char)j;
	}
	return(hex);
}

void convertToDsnForKeySet(const char* connectionString, char* dsnForKeySet, int dsnForKeySetLen)
{
	static char*	func = "convertToDsnForKeySet";
	char*			p = (char*)0;
	char*			pDbDsn = (char*)0;
	char			dbDsn[128], dbUid[128], dbPwd[128];

	getConnectionStringElement((char*)connectionString, "DSN=", dbDsn, sizeof(dbDsn));
	getConnectionStringElement((char*)connectionString, "Uid=", dbUid, sizeof(dbUid));
	getConnectionStringElement((char*)connectionString, "Pwd=", dbPwd, sizeof(dbPwd));
	pDbDsn = ((p = strstr(dbDsn, "@")) ? ++p : dbDsn);

	if (dbUid != nullptr && dbUid[0] != '\0' &&
		dbPwd != nullptr && dbPwd[0] != '\0')
	{
		sprintf_s(dsnForKeySet, dsnForKeySetLen, "%s:%s@%s", dbUid, dbPwd, pDbDsn);
	}
	else
	{
		sprintf_s(dsnForKeySet, dsnForKeySetLen, "%s", pDbDsn);
	}
}