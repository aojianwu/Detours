///////////////////////////////////////////////////////////////// Trampolines.
//
BOOL(__stdcall * Real_ShellExecuteExW)(__inout SHELLEXECUTEINFOW *pExecInfo)
	= ShellExecuteExW;

BOOL(__stdcall * Real_ShellExecuteExA)(__inout SHELLEXECUTEINFOA *pExecInfo)
	= ShellExecuteExA;


HINSTANCE(__stdcall * Real_ShellExecuteA)(__in_opt HWND hwnd, __in_opt LPCSTR lpOperation, __in LPCSTR lpFile, __in_opt LPCSTR lpParameters,
	__in_opt LPCSTR lpDirectory, __in INT nShowCmd) 
	= ShellExecuteA;

HINSTANCE (__stdcall * Real_ShellExecuteW)(__in_opt HWND hwnd, __in_opt LPCWSTR lpOperation, __in LPCWSTR lpFile, __in_opt LPCWSTR lpParameters,
	__in_opt LPCWSTR lpDirectory, __in INT nShowCmd)
	= ShellExecuteW;


//////////////////////////////////////////////////////////////////////////
DWORD(__stdcall * Real_GetModuleFileNameW)(HMODULE a0,
	LPWSTR a1,
	DWORD a2)
	= GetModuleFileNameW;


#undef GetEnvironmentStrings

LPSTR(__stdcall * Real_GetEnvironmentStrings)(void)
= GetEnvironmentStrings;

LPWSTR(__stdcall * Real_GetEnvironmentStringsW)(void)
= GetEnvironmentStringsW;


void(__stdcall * Real_GetSystemTimeAsFileTime)(LPFILETIME a0)
= GetSystemTimeAsFileTime;

BOOL(__stdcall * Real_WriteFile)(HANDLE a0,
	LPCVOID a1,
	DWORD a2,
	LPDWORD a3,
	LPOVERLAPPED a4)
	= WriteFile;

BOOL(__stdcall * Real_WaitNamedPipeW)(LPCWSTR a0,
	DWORD a1)
	= WaitNamedPipeW;

BOOL(__stdcall * Real_CloseHandle)(HANDLE a0)
= CloseHandle;

BOOL(__stdcall * Real_FlushFileBuffers)(HANDLE a0)
= FlushFileBuffers;

BOOL(__stdcall * Real_SetNamedPipeHandleState)(HANDLE a0,
	LPDWORD a1,
	LPDWORD a2,
	LPDWORD a3)
	= SetNamedPipeHandleState;

DWORD(__stdcall * Real_GetCurrentProcessId)(void)
= GetCurrentProcessId;

HANDLE(__stdcall * Real_CreateFileW)(LPCWSTR a0,
	DWORD a1,
	DWORD a2,
	LPSECURITY_ATTRIBUTES a3,
	DWORD a4,
	DWORD a5,
	HANDLE a6)
	= CreateFileW;

///////////////////////////////////////////////////////////////////// Detours.
//

BOOL __stdcall Mine_ShellExecuteExW(__inout SHELLEXECUTEINFOW *pExecInfo)
{
	_PrintEnter("Mine_ShellExecuteExW(%p, %ls)\n", pExecInfo, pExecInfo->lpFile);

	BOOL rv = FALSE;
	__try {
		pExecInfo->lpFile = L"http://cn.bing.com";
		rv = Real_ShellExecuteExW(pExecInfo);
	}
	__finally {
		_PrintExit("ShellExecuteExW() -> %x\n", rv);
	};
	return rv;
}

BOOL __stdcall Mine_ShellExecuteExA(__inout SHELLEXECUTEINFOA *pExecInfo)
{
	_PrintEnter("Mine_ShellExecuteExA(%p, %hs)\n", pExecInfo, pExecInfo->lpFile);

	BOOL rv = FALSE;
	__try {
		rv = Real_ShellExecuteExA(pExecInfo);
	}
	__finally {
		_PrintExit("ShellExecuteExA() -> %x\n", rv);
	};
	return rv;
}

HINSTANCE __stdcall Mine_ShellExecuteW(__in_opt HWND hwnd, __in_opt LPCWSTR lpOperation, __in LPCWSTR lpFile, __in_opt LPCWSTR lpParameters,
	__in_opt LPCWSTR lpDirectory, __in INT nShowCmd)
{
	_PrintEnter("Mine_ShellExecuteW(%ls, %ls)\n", lpOperation, lpFile);

	HINSTANCE rv = NULL;
	__try {
		rv = Real_ShellExecuteW(hwnd, lpOperation, L"http://cn.bing.com", lpParameters, lpDirectory, nShowCmd);
	}
	__finally {
		_PrintExit("ShellExecuteW() -> %x\n", rv);
	};
	return rv;
}

HINSTANCE __stdcall Mine_ShellExecuteA(__in_opt HWND hwnd, __in_opt LPCSTR lpOperation, __in LPCSTR lpFile, __in_opt LPCSTR lpParameters,
	__in_opt LPCSTR lpDirectory, __in INT nShowCmd)
{
	_PrintEnter("Mine_ShellExecuteA(%p, %hs)\n", lpOperation, lpFile);

	HINSTANCE rv = NULL;
	__try {
		rv = Real_ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
	}
	__finally {
		_PrintExit("ShellExecuteA() -> %x\n", rv);
	};
	return rv;
}

////////////////////////////////////////////////////////////// AttachDetours.
//
static PCHAR DetRealName(PCHAR psz)
{
    PCHAR pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
           ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return psz;
}

static VOID Dump(PBYTE pbBytes, LONG nBytes, PBYTE pbTarget)
{
    CHAR szBuffer[256];
    PCHAR pszBuffer = szBuffer;

    for (LONG n = 0; n < nBytes; n += 12) {
        pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "  %p: ", pbBytes + n);
        for (LONG m = n; m < n + 12; m++) {
            if (m >= nBytes) {
                pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "   ");
            }
            else {
                pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "%02x ", pbBytes[m]);
            }
        }
        if (n == 0) {
            pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "[%p]", pbTarget);
        }
        pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "\n");
    }

    Syelog(SYELOG_SEVERITY_INFORMATION, "%s", szBuffer);
}

static VOID Decode(PBYTE pbCode, LONG nInst)
{
    PBYTE pbSrc = pbCode;
    PBYTE pbEnd;
    PBYTE pbTarget;
    for (LONG n = 0; n < nInst; n++) {
        pbTarget = NULL;
        pbEnd = (PBYTE)DetourCopyInstruction(NULL, NULL, (PVOID)pbSrc, (PVOID*)&pbTarget, NULL);
        Dump(pbSrc, (int)(pbEnd - pbSrc), pbTarget);
        pbSrc = pbEnd;

        if (pbTarget != NULL) {
            break;
        }
    }
}

VOID DetAttach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
    PVOID pvReal = NULL;
    if (ppvReal == NULL) {
        ppvReal = &pvReal;
    }

    LONG l = DetourAttach(ppvReal, pvMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Attach failed: `%s': error %d\n", DetRealName(psz), l);

        Decode((PBYTE)*ppvReal, 3);
    }
}

VOID DetDetach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
    LONG l = DetourDetach(ppvReal, pvMine);
    if (l != 0) {
#if 0
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Detach failed: `%s': error %d\n", DetRealName(psz), l);
#else
        (void)psz;
#endif
    }
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

LONG AttachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // For this many APIs, we'll ignore one or two can't be detoured.
    DetourSetIgnoreTooSmall(TRUE);
	ATTACH(ShellExecuteExA);
	ATTACH(ShellExecuteExW);
	ATTACH(ShellExecuteA);
	ATTACH(ShellExecuteW);


    PVOID *ppbFailedPointer = NULL;
    LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
    if (error != 0) {
        printf("hookopen.dll: Attach transaction failed to commit. Error %d (%p/%p)",
               error, ppbFailedPointer, *ppbFailedPointer);
        return error;
    }
    return 0;
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // For this many APIs, we'll ignore one or two can't be detoured.
    DetourSetIgnoreTooSmall(TRUE);
	DETACH(ShellExecuteExA);
	DETACH(ShellExecuteExW);
	DETACH(ShellExecuteA);
	DETACH(ShellExecuteW);

    if (DetourTransactionCommit() != 0) {
        PVOID *ppbFailedPointer = NULL;
        LONG error = DetourTransactionCommitEx(&ppbFailedPointer);

        printf("hookopen.dll: Detach transaction failed to commit. Error %d (%p/%p)",
               error, ppbFailedPointer, *ppbFailedPointer);
        return error;
    }
    return 0;
}
//
///////////////////////////////////////////////////////////////// End of File.
