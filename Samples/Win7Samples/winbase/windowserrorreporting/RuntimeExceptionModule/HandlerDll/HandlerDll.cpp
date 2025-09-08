/*++

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    HandlerDll.c

Abstract:

    This sample demonstrates how to use the WER runtime exception callbacks.

    This module implements the runtime exception module DLL that handles out-of-process exceptions.

--*/

#include <stdio.h>
#include <crtdbg.h>
#include <stdarg.h>
#include <vector>

#include <windows.h>
#include <werapi.h>
#include <dbghelp.h>
#include <strsafe.h>
#include <sddl.h>

#define UNREACHABLE_CODE() _ASSERT(FALSE)

#pragma comment(lib, "dbghelp.lib")




// Helper function to write log entries with printf-style formatting
void WriteToLog(const char* format, ...) {
    // Buffer to hold the formatted message
    char message[1024];

    // Format the message using variable arguments
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Ensure null termination
    message[sizeof(message) - 1] = '\0';

    const char* path = "C:\\git\\tmp\\crash-log.txt";
    FILE* f = fopen(path, "a");

    if (f) {
        fputs(message, f);
        fputs("\n", f);
        fclose(f);
    }

    // Also try Windows Event Log
    HANDLE hEventLog = RegisterEventSourceA(NULL, "DDGWerTest");
    if (hEventLog) {
        const char* strings[] = { message };
        ReportEventA(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 1001, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }

#if 0
    // Also use OutputDebugString for debugger
    OutputDebugStringW((L"[DDG WER] " + message + L"\n").c_str());
#endif
}

class PrivilegeChecker {
public:
    static void PrintCurrentProcessPrivileges() {
        HANDLE hToken = NULL;

        // Open current process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            WriteToLog("Failed to open process token. Error: %lu", GetLastError());
            return;
        }

        WriteToLog("=== CURRENT PROCESS PRIVILEGE INFORMATION ===");

        PrintTokenUser(hToken);
        PrintTokenGroups(hToken);
        PrintTokenPrivileges(hToken);
        PrintTokenElevation(hToken);
        PrintTokenIntegrityLevel(hToken);
        PrintTokenType(hToken);

        CloseHandle(hToken);
    }

private:
    static void PrintTokenUser(HANDLE hToken) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

        std::vector<BYTE> buffer(dwSize);
        PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());

        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            LPWSTR pszSid = NULL;
            if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pszSid)) {
                WriteToLog("\n[USER INFORMATION]");
                // Convert wide string to multibyte for logging
                char szSidA[256];
                WideCharToMultiByte(CP_UTF8, 0, pszSid, -1, szSidA, sizeof(szSidA), NULL, NULL);
                WriteToLog("User SID: %s", szSidA);

                // Get account name
                WCHAR szName[256] = {0};
                WCHAR szDomain[256] = {0};
                DWORD dwNameSize = 256;
                DWORD dwDomainSize = 256;
                SID_NAME_USE sidType;

                                if (LookupAccountSidW(NULL, pTokenUser->User.Sid, szName, &dwNameSize,
                                     szDomain, &dwDomainSize, &sidType)) {
                    // Convert wide strings to multibyte for logging
                    char szNameA[256], szDomainA[256];
                    WideCharToMultiByte(CP_UTF8, 0, szName, -1, szNameA, sizeof(szNameA), NULL, NULL);
                    WideCharToMultiByte(CP_UTF8, 0, szDomain, -1, szDomainA, sizeof(szDomainA), NULL, NULL);
                    WriteToLog("User: %s\\%s", szDomainA, szNameA);
                }

                LocalFree(pszSid);
            }
        }
    }

    static void PrintTokenGroups(HANDLE hToken) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);

        std::vector<BYTE> buffer(dwSize);
        PTOKEN_GROUPS pTokenGroups = reinterpret_cast<PTOKEN_GROUPS>(buffer.data());

        if (GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
            WriteToLog("\n[GROUP MEMBERSHIPS]");

            for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                LPWSTR pszSid = NULL;
                if (ConvertSidToStringSidW(pTokenGroups->Groups[i].Sid, &pszSid)) {
                    WCHAR szName[256] = {0};
                    WCHAR szDomain[256] = {0};
                    DWORD dwNameSize = 256;
                    DWORD dwDomainSize = 256;
                    SID_NAME_USE sidType;

                                        if (LookupAccountSidW(NULL, pTokenGroups->Groups[i].Sid, szName,
                                         &dwNameSize, szDomain, &dwDomainSize, &sidType)) {
                        // Convert wide strings to multibyte for logging
                        char szNameA[256], szDomainA[256];
                        WideCharToMultiByte(CP_UTF8, 0, szName, -1, szNameA, sizeof(szNameA), NULL, NULL);
                        WideCharToMultiByte(CP_UTF8, 0, szDomain, -1, szDomainA, sizeof(szDomainA), NULL, NULL);

                        // Build attributes string
                        char szAttributes[256] = "(";
                        DWORD attrs = pTokenGroups->Groups[i].Attributes;
                        if (attrs & SE_GROUP_ENABLED) strcat_s(szAttributes, "Enabled ");
                        if (attrs & SE_GROUP_ENABLED_BY_DEFAULT) strcat_s(szAttributes, "Default ");
                        if (attrs & SE_GROUP_MANDATORY) strcat_s(szAttributes, "Mandatory ");
                        if (attrs & SE_GROUP_LOGON_ID) strcat_s(szAttributes, "LogonId ");
                        strcat_s(szAttributes, ")");

                        WriteToLog("  %s\\%s %s", szDomainA, szNameA, szAttributes);
                    }

                    LocalFree(pszSid);
                }
            }
        }
    }

    static void PrintTokenPrivileges(HANDLE hToken) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);

        std::vector<BYTE> buffer(dwSize);
        PTOKEN_PRIVILEGES pTokenPrivs = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());

        if (GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, dwSize, &dwSize)) {
            WriteToLog("\n[PRIVILEGES]");

            for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
                WCHAR szPrivName[256] = {0};
                DWORD dwNameSize = 256;

                                if (LookupPrivilegeNameW(NULL, &pTokenPrivs->Privileges[i].Luid,
                                        szPrivName, &dwNameSize)) {
                    // Convert wide string to multibyte for logging
                    char szPrivNameA[256];
                    WideCharToMultiByte(CP_UTF8, 0, szPrivName, -1, szPrivNameA, sizeof(szPrivNameA), NULL, NULL);

                    DWORD attrs = pTokenPrivs->Privileges[i].Attributes;
                    const char* status;
                    if (attrs & SE_PRIVILEGE_ENABLED)
                        status = "ENABLED";
                    else if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                        status = "ENABLED_BY_DEFAULT";
                    else
                        status = "DISABLED";

                    if (attrs & SE_PRIVILEGE_USED_FOR_ACCESS)
                        WriteToLog("  %s: %s (USED_FOR_ACCESS)", szPrivNameA, status);
                    else
                        WriteToLog("  %s: %s", szPrivNameA, status);
                }
            }
        }
    }

    static void PrintTokenElevation(HANDLE hToken) {
        WriteToLog("\n[ELEVATION STATUS]");

        // Check if token is elevated
        TOKEN_ELEVATION elevation = {0};
        DWORD dwSize = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, dwSize, &dwSize)) {
            WriteToLog("Is Elevated: %s", elevation.TokenIsElevated ? "YES" : "NO");
        }

        // Get elevation type
        TOKEN_ELEVATION_TYPE elevationType;
        dwSize = sizeof(TOKEN_ELEVATION_TYPE);

        if (GetTokenInformation(hToken, TokenElevationType, &elevationType, dwSize, &dwSize)) {
            const char* elevationDesc;
            switch (elevationType) {
                case TokenElevationTypeDefault:
                    elevationDesc = "Default (UAC disabled or standard user)";
                    break;
                case TokenElevationTypeFull:
                    elevationDesc = "Full (Elevated admin)";
                    break;
                case TokenElevationTypeLimited:
                    elevationDesc = "Limited (Non-elevated admin)";
                    break;
                default:
                    elevationDesc = "Unknown";
                    break;
            }
            WriteToLog("Elevation Type: %s", elevationDesc);
        }
    }

    static void PrintTokenIntegrityLevel(HANDLE hToken) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);

        std::vector<BYTE> buffer(dwSize);
        PTOKEN_MANDATORY_LABEL pTIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());

        if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
            DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
                (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

            WriteToLog("\n[INTEGRITY LEVEL]");

            const char* integrityDesc;
            if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                integrityDesc = "Low";
            else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
                integrityDesc = "Medium";
            else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
                integrityDesc = "High";
            else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
                integrityDesc = "System";
            else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
                integrityDesc = "Protected Process";
            else {
                WriteToLog("Integrity: Unknown (%lu)", dwIntegrityLevel);
                return;
            }
            WriteToLog("Integrity: %s", integrityDesc);
        }
    }

    static void PrintTokenType(HANDLE hToken) {
        TOKEN_TYPE tokenType;
        DWORD dwSize = sizeof(TOKEN_TYPE);

        if (GetTokenInformation(hToken, TokenType, &tokenType, dwSize, &dwSize)) {
            WriteToLog("\n[TOKEN TYPE]");
            WriteToLog("Type: %s", tokenType == TokenPrimary ? "Primary" : "Impersonation");
        }

        // If impersonation token, get impersonation level
        if (tokenType == TokenImpersonation) {
            SECURITY_IMPERSONATION_LEVEL impLevel;
            dwSize = sizeof(SECURITY_IMPERSONATION_LEVEL);

            if (GetTokenInformation(hToken, TokenImpersonationLevel, &impLevel, dwSize, &dwSize)) {
                const char* impDesc;
                switch (impLevel) {
                    case SecurityAnonymous:
                        impDesc = "Anonymous";
                        break;
                    case SecurityIdentification:
                        impDesc = "Identification";
                        break;
                    case SecurityImpersonation:
                        impDesc = "Impersonation";
                        break;
                    case SecurityDelegation:
                        impDesc = "Delegation";
                        break;
                    default:
                        impDesc = "Unknown";
                        break;
                }
                WriteToLog("Impersonation Level: %s", impDesc);
            }
        }
    }
};

// Simple usage function
void QuickPrivilegeCheck() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        WriteToLog("Failed to open token");
        return;
    }

    // Quick admin check
    TOKEN_ELEVATION elevation = {0};
    DWORD dwSize = sizeof(TOKEN_ELEVATION);

    if (GetTokenInformation(hToken, TokenElevation, &elevation, dwSize, &dwSize)) {
        WriteToLog("Running as Administrator: %s", elevation.TokenIsElevated ? "YES" : "NO");
    }

    // Check for specific privilege
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        PRIVILEGE_SET privSet = {0};
        privSet.PrivilegeCount = 1;
        privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privSet.Privilege[0].Luid = luid;
        privSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL hasPrivilege = FALSE;
        if (PrivilegeCheck(hToken, &privSet, &hasPrivilege)) {
            WriteToLog("Has SeDebugPrivilege: %s", hasPrivilege ? "YES" : "NO");
        }
    }

    CloseHandle(hToken);
}

const WCHAR* g_szDumpDirectory = L"C:\\git\\tmp\\dumps";
BOOL CreateCrashDump(
    const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInfo,
    LPWSTR pszDumpPath,
    DWORD cchDumpPath)
{
    BOOL bSuccess = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Get process ID from handle
    DWORD dwProcessId = GetProcessId(pExceptionInfo->hProcess);
    if (dwProcessId == 0)
        return FALSE;

    // Get thread ID from handle
    DWORD dwThreadId = GetThreadId(pExceptionInfo->hThread);
    if (dwThreadId == 0)
        return FALSE;

    // Ensure dump directory exists
    CreateDirectory(g_szDumpDirectory, NULL);

    // Generate unique filename
    SYSTEMTIME st;
    GetLocalTime(&st);
    StringCchPrintf(pszDumpPath, cchDumpPath,
        L"%s\\crash_%u_%04d%02d%02d_%02d%02d%02d.dmp",
        g_szDumpDirectory,
        dwProcessId,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    // Create dump file
    hFile = CreateFile(pszDumpPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        // Prepare exception information
        MINIDUMP_EXCEPTION_INFORMATION mdei = {0};
        mdei.ThreadId = dwThreadId;

        // Create EXCEPTION_POINTERS structure
        EXCEPTION_POINTERS exceptionPointers;
        exceptionPointers.ExceptionRecord = &pExceptionInfo->exceptionRecord;
        exceptionPointers.ContextRecord = &pExceptionInfo->context;
        mdei.ExceptionPointers = &exceptionPointers;
        mdei.ClientPointers = FALSE; // Pointers are in our process space now

        // Choose dump type
        MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
            MiniDumpNormal |
            MiniDumpFilterMemory
         );

        // Write dump using the provided process handle
        bSuccess = MiniDumpWriteDump(
            pExceptionInfo->hProcess,
            dwProcessId,
            hFile,
            dumpType,
            &mdei,
            NULL,
            NULL);

        CloseHandle(hFile);

        // If failed, delete the file
        if (!bSuccess)
        {
            DeleteFile(pszDumpPath);
        }
    }

    return bSuccess;
}


HRESULT WINAPI
OutOfProcessExceptionEventCallback (
  /* __in    */ PVOID pContext,
  /* __in    */ const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInformation,
  /* __out   */ BOOL *pbOwnershipClaimed,
  /* __out   */ PWSTR pwszEventName,
  /* __inout */ PDWORD pchSize,
  /* __out   */ PDWORD pdwSignatureCount
)

/*++

Routine Description:

    WER calls this function to determine whether the exception handler is claiming the crash.

    We will check if this is an exception we should handle (0xABCD1234).

    The PFN_WER_RUNTIME_EXCEPTION_EVENT type defines a pointer to this callback function.

    This function will be exported out of this DLL, as specified by HandlerDll.def.

Arguments:

    pContext - An arbitrary pointer-sized value that was passed in to WerRegisterRuntimeExceptionModule.

    pExceptionInformation - A WER_RUNTIME_EXCEPTION_INFORMATION structure that contains the exception
        information. Use the information to determine whether you want to claim the crash.

    pbOwnershipClaimed - Set to TRUE if you are claiming the crash; otherwise, FALSE. If you return FALSE,
        do not set the rest of the out parameters.

    pwszEventName - A caller-allocated buffer that you use to specify the event name used to identify this
        crash.

    pchSize - A pointer to a DWORD specifying the size, in characters, of the pwszEventName buffer. The size
        includes the null-terminating character.

    pdwSignatureCount - The number of report parameters that you will provide. The valid range of values is
        one to 10. If you specify a value greater than 10, WER will ignore the value and collect only the
        first 10 parameters. If you specify zero, the reporting process will be indeterminate.

        This value determines the number of times that WER calls your OutOfProcessExceptionEventSignature-
        Callback function.

Return Value:

    HRESULT.

--*/

{
    WriteToLog("[DDG WER] OutOfProcessExceptionEventCallback called for PID %lu, exception code 0x%08X",
        GetProcessId(pExceptionInformation->hProcess),
        pExceptionInformation->exceptionRecord.ExceptionCode);

    PrivilegeChecker::PrintCurrentProcessPrivileges();

    PCWSTR EventName = L"MySampleEventName";
    DWORD EventNameLength;


    UNREFERENCED_PARAMETER (pContext);


    //
    // Bail out if it is not an exception we want to handle.
    //
    // if (0xABCD1234 != pExceptionInformation->exceptionRecord.ExceptionCode) {
    //     *pbOwnershipClaimed = FALSE;
    //     return S_OK;
    // }

    //
    // Claim the exception. We will use 2 signature pairs to uniquely identify our exception.
    //
    *pbOwnershipClaimed = TRUE;
    *pdwSignatureCount = 2;

    //
    // See if the event name buffer given is big enough to hold the event name, and the null-terminator.
    //
    EventNameLength = (DWORD) (1 + wcslen (EventName));

    if (*pchSize < EventNameLength) {
        *pchSize = EventNameLength;
        return HRESULT_FROM_WIN32 (ERROR_INSUFFICIENT_BUFFER);
    }

    //
    // Copy the event name we use.
    //
    wcscpy_s (pwszEventName, *pchSize, EventName);

    WriteToLog("[DDG WER] Creating crash dump for process ID %lu...", GetProcessId(pExceptionInformation->hProcess));
    WCHAR szDumpPath[MAX_PATH];
    BOOL res = CreateCrashDump(pExceptionInformation, szDumpPath, MAX_PATH);
    if (res) {
        // Convert wide string to multibyte for logging
        char szDumpPathA[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, szDumpPath, -1, szDumpPathA, MAX_PATH, NULL, NULL);
        WriteToLog("[DDG WER] Created crash dump: %s", szDumpPathA);
    }
    else {
        WriteToLog("[DDG WER] Failed to create crash dump, error: %lu", GetLastError());
    }

    return S_OK;
}

HRESULT WINAPI
OutOfProcessExceptionEventSignatureCallback (
  /* __in    */ PVOID pContext,
  /* __in    */ const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInformation,
  /* __in    */ DWORD dwIndex,
  /* __out   */ PWSTR pwszName,
  /* __inout */ PDWORD pchName,
  /* __out   */ PWSTR pwszValue,
  /* __inout */ PDWORD pchValue
)

/*++

Routine Description:

    WER can call this function multiple times to get the report parameters that uniquely describe the
    problem.

    The PFN_WER_RUNTIME_EXCEPTION_EVENT_SIGNATURE type defines a pointer to this callback function.

    This function will be exported out of this DLL, as specified by HandlerDll.def.

Arguments:

    pContext - An arbitrary pointer-sized value that was passed in to WerRegisterRuntimeExceptionModule.

    pExceptionInformation - A WER_RUNTIME_EXCEPTION_INFORMATION structure that contains the exception
        information.

    dwIndex - The index of the report parameter. Valid values are 0 to 9.

    pwszName - A caller-allocated buffer that you use to specify the parameter name.

    pchName - A pointer to a DWORD specifying the size, in characters, of the pwszName buffer. The size includes
        the null-terminating character.

    pwszValue - A caller-allocated buffer that you use to specify the parameter value.

    pchValue - A pointer to a DWORD specifying the size, in characters, of the pwszValue buffer. The size includes
        the null-terminating character.

Return Value:

    HRESULT.

--*/

{
    WriteToLog("[DDG WER] OutOfProcessExceptionEventSignatureCallback called");
    UNREFERENCED_PARAMETER (pContext);


    //
    // Some sanity checks. Our handler only specifies 2 signature pairs.
    //
    if (dwIndex >= 2
        || (0xABCD1234 != pExceptionInformation->exceptionRecord.ExceptionCode)) {

        return E_UNEXPECTED;
    }

    //
    // Make sure the given buffers are large enough to hold our signature name/value pairs.
    // We will need 4 characters (3 characters + 1 null-terminator) for our fixed strings.
    //
    if (*pchName < 4) {
        *pchName = 4;
        return HRESULT_FROM_WIN32 (ERROR_INSUFFICIENT_BUFFER);
    }

    if (*pchValue < 4) {
        *pchValue = 4;
        return HRESULT_FROM_WIN32 (ERROR_INSUFFICIENT_BUFFER);
    }

    //
    // At this point, we should fill in the problem signature with the data from the crashing process.
    //
    // For example, the signature can uniquely identify where the crash happened. If our application runs
    // custom-compiled code, we can let the signature identify what module/class/line/etc the crash
    // happened at. This can be done by exposing an easily-accessible data structure in the process, and
    // reading the structure using ReadProcessMemory.
    //
    // In here, we will simply set the signature to some fixed strings.
    //
    switch (dwIndex) {
      case 0:
        wcscpy_s (pwszName, *pchName, L"one");
        wcscpy_s (pwszValue, *pchValue, L"111");
        break;

      case 1:
        wcscpy_s (pwszName, *pchName, L"two");
        wcscpy_s (pwszValue, *pchValue, L"222");
        break;

      default:
        UNREACHABLE_CODE ();
    }

    return S_OK;
}

HRESULT WINAPI
OutOfProcessExceptionEventDebuggerLaunchCallback (
  /* __in    */ PVOID pContext,
  /* __in    */ const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInformation,
  /* __out   */ PBOOL pbIsCustomDebugger,
  /* __out   */ PWSTR pwszDebuggerLaunch,
  /* __inout */ PDWORD pchDebuggerLaunch,
  /* __out   */ PBOOL pbIsDebuggerAutolaunch
)

/*++

Routine Description:

    WER calls this function to let you customize the debugger launch options and launch string.

    The PFN_WER_RUNTIME_EXCEPTION_DEBUGGER_LAUNCH type defines a pointer to this callback function.

    This function will be exported out of this DLL, as specified by HandlerDll.def.

Arguments:

    pContext - An arbitrary pointer-sized value that was passed in to WerRegisterRuntimeExceptionModule.

    pExceptionInformation - A WER_RUNTIME_EXCEPTION_INFORMATION structure that contains the exception
        information.

    pbIsCustomDebugger - Set to TRUE if you want to use the custom debugger specified in the
        pwszDebuggerLaunch parameter; otherwise, FALSE to use the default debugger. If you return FALSE, do
        not set the pwszDebuggerLaunch parameter.

    pwszDebuggerLaunch - A caller-allocated buffer that you use to specify the debugger launch string used to
        launch the debugger.

        The launch string must include the full path to the debugger and any arguments. If an argument
        ncludes multiple words, use quotes to delimit the argument.

    pchDebuggerLaunch - A pointer to a DWORD specifying the size, in characters, of the pwszDebuggerLaunch buffer.
        The size includes the null-terminating character.

    pbIsDebuggerAutolaunch - Set to TRUE if you want WER to silently launch the debugger; otherwise, FALSE if
        you want WER to ask the user before launching the debugger.

Return Value:

    HRESULT.

--*/

{
    WriteToLog("[DDG WER] OutOfProcessExceptionEventDebuggerLaunchCallback called");
    UNREFERENCED_PARAMETER (pContext);


    //
    // Some sanity checks.
    //
    if ((0xABCD1234 != pExceptionInformation->exceptionRecord.ExceptionCode)) {
        return E_UNEXPECTED;
    }

    //
    // Specify that we won't be using any custom debugger for this.
    //
    *pbIsCustomDebugger = FALSE;

    return S_OK;
}

BOOL WINAPI
DllMain (
    HINSTANCE DllInstance,
    DWORD Reason,
    LPVOID Reserved
)

{
    WriteToLog("[DDG WER] DllMain called with reason: %lu", Reason);
    UNREFERENCED_PARAMETER (DllInstance);
    UNREFERENCED_PARAMETER (Reason);
    UNREFERENCED_PARAMETER (Reserved);


    return TRUE;
}
