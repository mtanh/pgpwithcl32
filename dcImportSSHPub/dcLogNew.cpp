//#include <WinReg.h>
#include <Windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> // toupper
#include <ctype.h> // toupper
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <algorithm>

#include "dcLogNew.h"

#define GET_THREAD_ID() (GetCurrentThreadId())
#define GET_PROCESS_ID() (GetCurrentProcessId())

static const int LOG_DATE_BUF_SIZE = 10;
static const int LOG_MESSAGE_OUTPUT_BUFFER_SIZE = 5000;
static const int MAX_PATH_LEN = 1024;
static const int MAX_TAGS = 1024;
static const char* LOG_FILETYPE = ".log";
static int GlobalLogFileTable[LOG_COUNT];
static int singleLogFile;
static const char *logFileNames[] = {
	"IN",		// Info
	"ER",		// Error
	"WN",		// Warning
	"DB",		// Debug
	"TR"		// Trace
};
static int GlobalLogStatus[] = {
	false,
	false,
	false,
	false,
	true
};
static ULONG GlobalNumStrTags = 0; //number of enabled string tags
static LPCSTR GlobalStrTagPtrs[MAX_TAGS]; // sorted pointers to enabled string tags
static char GlobalStrTags[10240]; // enabled string tags: list of NUL terminated strings ended with a NUL
static ULONG GlobalTagMask1 = 0; // enabled mask tags
static ULONG GlobalTagMask2 = 0;
static ULONG GlobalNumTagBase = 0; // base for numeric tags (tags are in range base+1,...,base+8*MAX_TAGS
static ULONG GlobalNumTagMasks[MAX_TAGS]; // enabled numeric tags (tag used as index into array of bit masks)
static bool initialized = false;
static bool logToFile = false;
static bool useSingleFile = true;
static bool switchFiles = false;
static bool autoPurge = false;
static time_t autoPurgePeriod = 0;
static bool seekToEnd = false;
static bool logProcessId = false;
static bool logMillisecs = false;
static bool logDate = true;
static bool logFile = true;
static char autoPurgeRegExpList[MAX_AUTO_PURGE_REG_EXP_LEN];
static bool logThreadId = false;
static bool writeToConsole = false;

// Number of days' log files to keep.
// 0 means keep everything.
static int nKeep = DEFAULT_NKEEP;
static int nFiles = 0; // Keep track of number of files, for pruning
static time_t* timeStamps = NULL; // timestamps of previous files
static char strLogDir[MAX_PATH_LEN];
static char filenamePrefix[MAX_FILENAME_PREFIX_LEN];
static char	dateBuf[LOG_DATE_BUF_SIZE];

static const int MINLOGSIZE = 1; //1MB is the minimum log file size we are maintaining
static const int SIZE_METRIC = 1024 * 1024; //Mega Bytes
static const int MAXLOGFILESIZE = 20 * SIZE_METRIC; //20MB is the maximum application will write regardless
													//of any variable set in the registry
static bool bStopWrite = false;
static DWORD g_maxFileSize = MAXLOGFILESIZE;
static DWORD nCurrLogFileSize = 0;
static time_t nextLogSwitchTime; // Time when to close current log file and open a new one

static CRITICAL_SECTION LogCriticalSection;
static void OpenLogFiles();
static void CloseLogFiles();
static void LogWrite(LPCSTR file, int line, LogType logType, LPSTR szBuf);

void InitLog(const char* logDir, const char* filenamePrefixA, bool useSingleFileA, bool switchFilesA, int nKeepA)
{
	if (initialized) {
		return;
	}

	InitializeCriticalSection(&LogCriticalSection);
	memset(&GlobalNumTagMasks[0], 0, sizeof(GlobalNumTagMasks));
	singleLogFile = -1;
	std::fill(GlobalLogFileTable, GlobalLogFileTable + LOG_COUNT, -1);
	/*for(int i = 0; i < LOG_COUNT; ++i) {
	GlobalLogFileTable[i] = -1;
	}*/

	if (logDir)
	{
		strcpy(strLogDir, (char*)logDir);
		if (filenamePrefixA)
		{
			strncpy(filenamePrefix, filenamePrefixA, sizeof(filenamePrefix));
			filenamePrefix[sizeof(filenamePrefix) - 1] = '\0';
		}
		useSingleFile = useSingleFileA;
		logToFile = true;
		switchFiles = switchFilesA;
		if (nKeep == nKeepA)
		{
			timeStamps = new time_t[nKeep];

			// NOTE: Important to initialize to 0.
			memset(timeStamps, 0, sizeof(*timeStamps) * nKeep);
		}
		else
		{
			timeStamps = new time_t[nKeepA];

			// NOTE: Important to initialize to 0.
			memset(timeStamps, 0, sizeof(*timeStamps) * nKeepA);
		}
		OpenLogFiles();
	}
	else
	{
		logToFile = false;
		switchFiles = false;
		autoPurge = false;
	}

#ifdef _DEBUG
	if (autoPurge && !switchFiles)
	{
		assert(false);
	}
#endif	// _DEBUG

	initialized = true;
}

LOG_DECL void InitLogEx(const char* logDir,
	const char* filenamePrefixA,
	unsigned long optionsA,
	int nKeepA)
{
	if (initialized)
	{
		return;
	}

	bool useSingleFileLocal;
	bool switchFilesLocal;
	bStopWrite = false;
	DWORD regFileSize = 1; // 1MB for log file

	if (regFileSize > 0)
	{
		if (regFileSize >= MINLOGSIZE) //should be at least Min log size
		{
			g_maxFileSize = regFileSize * SIZE_METRIC; //g_maxfilesize is in bytes
		}
	}


	useSingleFileLocal = (optionsA & LOG_OPTION_USE_SINGLE_FILE) ? true : false;
	switchFilesLocal = (optionsA & LOG_OPTION_SWITCH_FILES) ? true : false;

	logThreadId = (optionsA & LOG_OPTION_LOG_THREAD_ID) ? true : false;
	writeToConsole = (optionsA & LOG_OPTION_WRITE_TO_CONSOLE) ? true : false;
	autoPurge = (optionsA & LOG_OPTION_AUTO_PURGE) ? true : false;
	seekToEnd = (optionsA & LOG_OPTION_SEEK_TO_END) ? true : false;
	logProcessId = (optionsA & LOG_OPTION_LOG_PROCESS_ID) ? true : false;
	logMillisecs = (optionsA & LOG_OPTION_LOG_MILLISECS) ? true : false;
	logDate = (optionsA & LOG_OPTION_LOG_DATE) ? true : false;
	logFile = (optionsA & LOG_OPTION_LOG_FILENAME) ? true : false;
	autoPurgePeriod = DEFAULT_AUTO_PURGE_PERIOD;

	// Default regular expression is derived from filename prefix
	sprintf(autoPurgeRegExpList, "%s*%s", filenamePrefixA, LOG_FILETYPE);

	// Chain to the original InitLog
	InitLog(logDir, filenamePrefixA, useSingleFileLocal, switchFilesLocal, nKeepA);
}

void EndLog(void)
{
	if (initialized)
	{
		if (logToFile)
		{
			CloseLogFiles();
		}
	}
	initialized = false;
	if (timeStamps) {
		delete[] timeStamps;
	}
}

void LogPrintf(LogType logType, const char* fmt, ...)
{
	va_list marker;
	char szBuf[LOG_MESSAGE_OUTPUT_BUFFER_SIZE];

	assert((int)logType < LOG_COUNT);

	// If message type not enabled do not log
	if (!initialized || !GlobalLogStatus[logType]) {
		return;
	}

	va_start(marker, fmt);
	vsnprintf(szBuf, sizeof szBuf, fmt, marker);
	va_end(marker);

	LogWrite(NULL, 0, logType, szBuf);
}

void EnableLog(LogType logType)
{
	GlobalLogStatus[logType] = true;
}

void DisableLog(LogType logType)
{
	GlobalLogStatus[logType] = false;
}

void SetLogMask(int mask)
{
	int i;

	// Need array to map enum value to bit position,
	// because they don't match.
	static int maskBits[LOG_COUNT] =
	{
		LOG_INFO_BIT,
		LOG_ERROR_BIT,
		LOG_WARNING_BIT,
		LOG_DEBUG_BIT,
		LOG_TRACE_BIT
	};

	for (i = 0; i < LOG_COUNT; ++i)
	{
		if (mask & maskBits[i])
		{
			EnableLog((LogType)i);
		}
		else
		{
			DisableLog((LogType)i);
		}
	}
}

unsigned long LogMaskStr2Mask(const char* maskStr)
{
	int c;
	unsigned long mask;

	for (mask = 0; (c = *maskStr); ++maskStr)
	{
		// Make case-insensitive
		if (islower(c))
		{
			c = toupper(c);
		}

		switch (c) {
		case 'D':
			mask |= LOG_DEBUG_BIT;
			break;
		case 'I':
			mask |= LOG_INFO_BIT;
			break;
		case 'W':
			mask |= LOG_WARNING_BIT;
			break;
		case 'E':
			mask |= LOG_ERROR_BIT;
			break;
		case 'A':
			mask |= LOG_ALL_BITS;
			break;
		default:
			// Ignore anything that's not recognized
			assert(false);
			break;
		}
	}

	return (mask);
}

void DeleteExpiredLogs(const char* logDir, const char* logFiles, time_t logExpirationPeriod)
{
	time_t			ft;
	time_t			now;
	HANDLE			fh;
	struct tm       *lt;
	FILETIME		lft;
	SYSTEMTIME		st;
	WIN32_FIND_DATA fd;
	char			logPath[512];
	char			fullName[512];
	char			regExp[32];
	const char*		cp;

	// Process regular expressions, one at a time
	//
	for (cp = logFiles; ; )
	{
		int nChars;
		LPCSTR commaPos;
		LPCSTR end;

		commaPos = strchr(cp, ',');
		if (!commaPos)
		{
			end = cp + strlen(cp);
		}
		else
		{
			end = commaPos;
		}

		nChars = end - cp;
		strncpy(regExp, cp, nChars);
		regExp[nChars] = '\0';

		strcpy(logPath, logDir);
		strcat(logPath, regExp);
		now = time(NULL);

		if ((fh = FindFirstFile(logPath, &fd)) != INVALID_HANDLE_VALUE)
		{
			do {
				if (!(FileTimeToLocalFileTime(&fd.ftCreationTime, &lft)
					&& FileTimeToSystemTime(&lft, &st)))
				{
					continue;
				}

				lt = localtime(&now);
				lt->tm_sec = st.wSecond;
				lt->tm_min = st.wMinute;
				lt->tm_hour = st.wHour;
				lt->tm_mday = st.wDay;
				lt->tm_mon = st.wMonth - 1;
				lt->tm_year = st.wYear - 1900;
				lt->tm_wday = st.wDayOfWeek;

				ft = mktime(lt);
				if (now - ft >= logExpirationPeriod)
				{
					strcpy(fullName, logDir);
					strcat(fullName, fd.cFileName);
					_unlink(fullName);
				}
			} while (FindNextFile(fh, &fd));

			(void)FindClose(fh);
		}

		if (!commaPos)
		{
			break;
		}

		cp = commaPos + 1;
	}
}

void LogWrite(LPCSTR file, int line, LogType logType, LPSTR szBuf)
{
	int pLogFile;
	char msgBuf[LOG_MESSAGE_OUTPUT_BUFFER_SIZE + 512]; //add 512 for threadId, strTime, logFileNames, etc
	struct _timeb tval;
	char *strTime;
	_ftime(&tval);	// GMT


					// Switch log files if needed

	if (switchFiles && (tval.time >= nextLogSwitchTime))
	{
		// Protect against multiple threads doing this simultaneously

		EnterCriticalSection(&LogCriticalSection);
		bStopWrite = false;
		nCurrLogFileSize = 0;

		// Check condition again after acquiring lock.
		// See comments in OpenLogFiles() about setting 'nextLogSwitchTime'.
		if (tval.time >= nextLogSwitchTime)
		{
			CloseLogFiles();
			OpenLogFiles();
			LeaveCriticalSection(&LogCriticalSection);

			// Purge old files here. There is no need to hold the lock
			// (and make the other threads wait) while doing this
			// because only one thread should be in this part of the 'if'.
			if (autoPurge)
			{
				DeleteExpiredLogs(strLogDir, autoPurgeRegExpList, autoPurgePeriod);
			}
		}
		else
		{
			LeaveCriticalSection(&LogCriticalSection);
		}
	}

	//end removal of log files

	// remove trailing newlines from message
	int msgLen = strlen(szBuf);
	while (msgLen > 0 && szBuf[msgLen - 1] == '\n') {
		msgLen--;
	}

	if (msgLen < (int)sizeof(szBuf)) {
		szBuf[msgLen] = '\0';
	}

	strTime = ctime(&tval.time);
	strTime += 4;
	if (!logDate) {
		strTime += 7;
	}
	strTime[strlen(strTime) - 6] = '\0';

	char threadId[20];
	char* cp;
	*threadId = '\0';
	cp = threadId;
	if (logProcessId)
	{
		sprintf(cp, "%08X", (unsigned)GET_PROCESS_ID());
		cp += 8;
		assert(!*cp);	// must be null terminator
	}
	if (logThreadId)
	{
		// If process id was written, add separator
		if (*threadId)
		{
			*cp++ = ':';
		}
		sprintf(cp, "%08X", GET_THREAD_ID());
		cp += 8;
		assert(!*cp);	// must be null terminator
	}
	// If processId/threadId/both were written, add space
	if (*threadId)
	{
		*cp++ = ' ';
		*cp = '\0';
	}

	int nChars;

	if (useSingleFile)
	{
		if (logFile && file != NULL && (logType == LOG_DEBUG || logType == LOG_TRACE))
		{
			if (logMillisecs)
			{
				nChars = sprintf(msgBuf, "%s%s.%03u %s: %s/%d- %s\n",
					threadId,
					strTime,
					tval.millitm,
					logFileNames[logType],
					file,
					line,
					szBuf);
			}
			else
			{
				nChars = sprintf(msgBuf, "%s%s %s: %s/%d- %s\n",
					threadId,
					strTime,
					logFileNames[logType],
					file,
					line,
					szBuf);
			}
		}
		else
		{
			if (logMillisecs)
			{
				nChars = sprintf(msgBuf, "%s%s.%03u %s: %s\n",
					threadId,
					strTime,
					tval.millitm,
					logFileNames[logType],
					szBuf);
			}
			else
			{
				nChars = sprintf(msgBuf, "%s%s %s: %s\n",
					threadId,
					strTime,
					logFileNames[logType],
					szBuf);
			}
		}
	}
	else if (logFile && file != NULL && (logType == LOG_DEBUG || logType == LOG_TRACE))
	{
		if (logMillisecs)
		{
			nChars = sprintf(msgBuf, "%s%s.%03u %s/%d- %s\n",
				threadId,
				strTime,
				tval.millitm,
				file,
				line,
				szBuf);
		}
		else
		{
			nChars = sprintf(msgBuf, "%s%s %s/%d- %s\n",
				threadId,
				strTime,
				file,
				line,
				szBuf);
		}
	}
	else
	{
		if (logMillisecs)
		{
			nChars = sprintf(msgBuf, "%s%s.%03u %s\n",
				threadId,
				strTime,
				tval.millitm,
				szBuf);
		}
		else
		{
			nChars = sprintf(msgBuf, "%s%s %s\n",
				threadId,
				strTime,
				szBuf);
		}
	}

	// If there are two \n's at the end, get rid of the second one.
	if ((nChars >= 2) && ('\n' == msgBuf[nChars - 1]) && ('\n' == msgBuf[nChars - 2]))
	{
		msgBuf[nChars - 1] = '\0';
	}

	// Output to any interested debuggers
	OutputDebugString(msgBuf);

	// For console applications, write to console window as well
	if (writeToConsole)
	{
		fputs(msgBuf, stdout);
		fflush(stdout);
	}


	if (bStopWrite == true)
	{
		//this means we do not write to the log file anymore
		//as it has exceeded the maximum size
		return;
	}

	if (!logToFile) {
		return;
	}

	if (useSingleFile)
	{
		pLogFile = singleLogFile;
	}
	else
	{
		pLogFile = GlobalLogFileTable[(int)logType];
	}

	if (pLogFile >= 0)
	{
		if (seekToEnd)
		{
			(void)_lseek(pLogFile, 0, SEEK_END);
		}

		//nCurrLogFileSize = _lseek(pLogFile, 0, SEEK_CUR);
		//if(nCurrLogFileSize >= g_maxFileSize)
		//{
		//	bStopWrite = true;
		//	sprintf(msgBuf,
		//		"Log has Reached or Exceeded size Limit of %d bytes;Disabling further Logging for Today\n",
		//		g_maxFileSize);
		//	//return;
		//}

		(void)_write(pLogFile, msgBuf, strlen(msgBuf));
	}
}

void OpenLogFiles()
{
	TCHAR szLogFile[128];
	TCHAR deleteFilename[LOG_DATE_BUF_SIZE];
	int logIndex;
	int pLogFile;
	char *pLogFileBase;
	time_t timeNow;
	struct tm *pTm;
	time_t timeDelete = 0;

	if (!logToFile || !strLogDir[0]) {
		return;
	}

	timeNow = time(0);
	pTm = localtime(&timeNow);
	sprintf(dateBuf, "%04d%02d%02d",
		pTm->tm_year + 1900, pTm->tm_mon + 1, pTm->tm_mday);


	// NOTE: reusing pTm
	//
	if (nKeep)
	{
		timeDelete = timeStamps[nFiles % nKeep];
		timeStamps[nFiles % nKeep] = timeNow;
		++nFiles;
		if (timeDelete)
		{
			pTm = localtime(&timeDelete);

			sprintf(deleteFilename, "%04d%02d%02d",
				pTm->tm_year + 1900, pTm->tm_mon + 1, pTm->tm_mday);
		}
	}

	strcpy(szLogFile, strLogDir);
	pLogFileBase = szLogFile + strlen(szLogFile);

	for (logIndex = 0; logIndex < LOG_COUNT; logIndex++)
	{
		strcpy(pLogFileBase, filenamePrefix);
		// If logging to multiple files, prefix each file
		// with the type of messages in that file.
		if (!useSingleFile)
		{
			strcat(pLogFileBase, logFileNames[logIndex]);
		}
		strcat(pLogFileBase, dateBuf);
		strcat(pLogFileBase, LOG_FILETYPE);

		// Delete old logs
		// We try to open today's log file
		// if it does not exist- i.e. this is the first time the application is being run today
		// then we remove all the old logs, over 10 days old
		// if today's log file exists,then we do not check - we check only once,everyday
		// at the first time when the application in run

		pLogFile = _open(szLogFile, O_RDONLY, _S_IREAD);
		if (pLogFile == -1)
		{
			// file does not exist - this is the first time we r running the application
			// delete all old log files,if they are over 10 days old
			if (autoPurge) {
				DeleteExpiredLogs(strLogDir, autoPurgeRegExpList, autoPurgePeriod);
			}

		}
		else //the today's log file exists - close it
		{
			(void)_close(pLogFile);
		}

		pLogFile = _open(szLogFile, O_APPEND | O_WRONLY | O_CREAT, _S_IREAD | _S_IWRITE);

		// If keeping only a fixed number of log files, delete
		// the oldest one. Do this before checking pLogFile, since
		// we may return if the fopen above failed.
		// NOTE: reusing szLogFile.
		if (timeDelete)
		{
			strcpy(pLogFileBase, filenamePrefix);
			// If logging to multiple files, prefix each file
			// with the type of messages in that file.
			if (!useSingleFile)
			{
				strcat(pLogFileBase, logFileNames[logIndex]);
			}
			strcat(pLogFileBase, deleteFilename);
			strcat(pLogFileBase, LOG_FILETYPE);
			(void)_unlink(szLogFile);
		}

		if (pLogFile == -1)
		{
#ifdef _DEBUG
			OutputDebugString("***** ERROR ***** Could not open logfile ");
			OutputDebugString(szLogFile);
			OutputDebugString("\n");
#endif	// _DEBUG
			logToFile = false;
			return;
		}
		if (useSingleFile)
		{
			// If logging everything to one file, we're done
			singleLogFile = pLogFile;
			break;
		}
		else
		{
			GlobalLogFileTable[logIndex] = pLogFile;
		}
	}

	// Set "nextLogSwitchTime" after opening the log file(s).
	// Otherwise, other threads can try to use the file handles in
	// LogPrintf() before the log files are opened.
	pTm = localtime(&timeNow);

	// Set nextLogSwitchTime to midnight
	// Calculate our timezone adjustment
	time_t adjustTime;
	adjustTime = _timezone - ((60 * 60) * pTm->tm_isdst);

	// nextLogSwitchTime is in local time
	nextLogSwitchTime = timeNow - adjustTime;
	// Calculate seconds left till midnight
	nextLogSwitchTime = nextLogSwitchTime - (nextLogSwitchTime % (24 * 60 * 60)) + (24 * 60 * 60);
	// switch back to GMT for comparisons with time()
	nextLogSwitchTime += adjustTime;
}

void CloseLogFiles()
{
	TCHAR szLogFile[128];
	char  errLogFile[512];
	int logIndex;
	char *pLogFileBase;
	struct stat st;

	if (!logToFile || !strLogDir[0]) {
		return;
	}

	strcpy(szLogFile, strLogDir);
	strcpy(errLogFile, strLogDir);
	strcat(errLogFile, "VNE");
	pLogFileBase = szLogFile + strlen(szLogFile);

	for (logIndex = 0; logIndex < LOG_COUNT; logIndex++)
	{
		strcpy(pLogFileBase, filenamePrefix);

		// If logging to multiple files, prefix each file
		// with the type of messages in that file.
		if (!useSingleFile)
		{
			strcat(pLogFileBase, logFileNames[logIndex]);
		}
		strcat(pLogFileBase, dateBuf);
		strcat(errLogFile, dateBuf);
		strcat(errLogFile, ".log");
		strcat(pLogFileBase, LOG_FILETYPE);
		if (stat(szLogFile, &st) == -1)
		{
			OutputDebugString("Cannot stat log file\n");

			FILE *err;
			err = fopen(errLogFile, "a");
			if (err != NULL)
			{
				fprintf(err, "Cannot stat log file %s\n", szLogFile);
				fclose(err);
			}
			continue;
		}

		if (st.st_size == 0) {
			(void)_unlink(szLogFile);
		}

		if (useSingleFile)
		{
			// If logging everything to one file, we're done
			(void)_close(singleLogFile);
			singleLogFile = -1;
			break;
		}
		else if (GlobalLogFileTable[logIndex])
		{
			(void)_close(GlobalLogFileTable[logIndex]);
			GlobalLogFileTable[logIndex] = -1;
		}
	}
}

void SetAutoPurgePeriod(int autoPurgePeriodA)
{
	// Purge period is in days.
	autoPurgePeriod = autoPurgePeriodA * 24 * 60 * 60;
	assert(autoPurgePeriod >= (24 * 60 * 60));
	if (!autoPurgePeriod)
	{
		autoPurge = false;
	}
}
