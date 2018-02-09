#pragma once

#include <time.h>

#ifdef __cplusplus
#define LOG_DECL extern "C" __declspec(dllexport)
#else
#define LOG_DECL __declspec(dllexport)
#endif

// Keep last 5 days' log files around
const int DEFAULT_NKEEP = 5;
const int MAX_FILENAME_PREFIX_LEN = 32;	// including null-terminator
const int MAX_AUTO_PURGE_REG_EXP_LEN = 64;
const int DEFAULT_AUTO_PURGE_PERIOD = ((DEFAULT_NKEEP) * 24 * 60 * 60);
const int LOG_COUNT = 5;

typedef enum {
	LOG_INFO,
	LOG_ERROR,
	LOG_WARNING,
	LOG_DEBUG,
	LOG_TRACE
} LogType;

// Note that the bit positions and the enum values don't match.
// Not changing enum's because it may break something.
// These bit positions are in the order of severity.
#define LOG_DEBUG_BIT 0x01
#define LOG_INFO_BIT 0x02
#define LOG_WARNING_BIT 0x04
#define LOG_ERROR_BIT 0x08
#define LOG_TRACE_BIT 0x10
#define LOG_ALL_BITS (LOG_DEBUG_BIT|LOG_INFO_BIT|LOG_WARNING_BIT|LOG_ERROR_BIT|LOG_TRACE_BIT)

// Log options
#define LOG_OPTION_USE_SINGLE_FILE 0x00000001
// Write all types of messages to same file or different types
// (debug, info, etc) to different files ?
#define LOG_OPTION_SWITCH_FILES	0x00000002
// Switch files every midnight ?
// Note that the actual switch may not happen at midnight - it happens
// only when the first message is logged after midnight.
#define LOG_OPTION_LOG_THREAD_ID 0x00000004
// Write the current thread ID with each message ?
#define LOG_OPTION_WRITE_TO_CONSOLE	0x00000008
// Write to the console (ie: printf(msg)) ?
#define LOG_OPTION_AUTO_PURGE 0x00000010
// Purge old files when switching ?
// Note that you must turn on SWITCH_FILES for this to work.
#define LOG_OPTION_SEEK_TO_END 0x00000020
// Always seek to the end of the file before writing ?
// This was added to handle the case where multiple processes
// can write to the same log file. The processes still
// have to coordinate writing to the log file (using a system-wide mutex).
#define LOG_OPTION_LOG_PROCESS_ID 0x00000040
// Write the process ID with each message ?
#define LOG_OPTION_LOG_DATE 0x00000080
// Write the date with each message ?
#define LOG_OPTION_LOG_MILLISECS 0x00000100
// Include milliseconds in timestamp with each message ?
#define LOG_OPTION_LOG_FILENAME 0x00000200
// Include filename/line number with each debug or trace message ?

LOG_DECL void InitLog(const char* logDir, const char* filenamePrefixA, bool useSingleFileA,
	bool switchFilesA, int nKeepA);
LOG_DECL void InitLogEx(const char* logDir, const char* filenamePrefixA, unsigned long optionsA, int nKeepA);
LOG_DECL void SetAutoPurgePeriod(int autoPurgePeriodA);
LOG_DECL void EndLog(void);
LOG_DECL void LogPrintf(LogType logType, const char* fmt, ...);
LOG_DECL void EnableLog(LogType logType);
LOG_DECL void DisableLog(LogType logType);
LOG_DECL void SetLogMask(int mask);
LOG_DECL unsigned long LogMaskStr2Mask(const char* maskStr);

// Delete log files older than the given time (in secs)
// "logFiles" is a comma-separated list of regular expressions.
// eg: "DICFTP*.log, DICAS2*.log"
// This means that ',' cannot be used in log filenames.
// "logFiles" should not contain any spaces.
LOG_DECL void DeleteExpiredLogs(const char* logDir, const char* logFiles, time_t logExpirationPeriod);