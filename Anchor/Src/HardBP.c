#include "HardBP.h"

// insert a "ret" instruction
#pragma section(".text")
__declspec(allocate(".text")) const BYTE bRet = 0xc3;

BOOL GlobalBounce[4] = { FALSE, FALSE, FALSE, FALSE };

PVOID VEHexceptionHandler = NULL;
CRITICAL_SECTION CritSection = { 0 };
BOOL CritSectionInit = FALSE;

PVOID pBounceFunction[4] = { 0 };

VOID RetFunc(CONTEXT* ctx) {
	ctx->Rip = (DWORD64)&bRet;
}

VOID MessageBoxFunc() {
	MessageBoxW(NULL, L"Hardware Breakpoint hook executed!", L"Anchor", MB_OK | MB_ICONEXCLAMATION);
}

VOID BounceFunc(CONTEXT* ctx) {
	HANDLE hWindow = CreateThread(NULL, NULL, MessageBoxFunc, NULL, NULL, NULL);
	if (hWindow == NULL) {
		printf("\n[!] Error creating the message box - %d\n", GetLastError());
		return;
	}
	CloseHandle(hWindow);
}

BOOL InitHardBp() {
	if (CritSectionInit == FALSE) {
		InitializeCriticalSection(&CritSection);
		CritSectionInit = TRUE;
	}

	if (VEHexceptionHandler == NULL) {
		if ((VEHexceptionHandler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&VEHfunction)) == NULL) {
			printf("\n[!] Error setting the VEH exception handler - %d\n", GetLastError());
			return FALSE;
		}
	}
	return TRUE;
}

BOOL Cleanup() {
	EnterCriticalSection(&CritSection);
	for (int i = 0; i < 4; i++) {
		RemHardBp(i);
	}
	LeaveCriticalSection(&CritSection);
	return TRUE;
}

BOOL SetHardBp(IN PVOID pAddress, IN PVOID fnHookFunc, IN enum DRreg tempDRreg) {
	if (fnHookFunc == NULL || pAddress == NULL || VEHfunction == NULL) return FALSE;

	EnterCriticalSection(&CritSection);
	pBounceFunction[tempDRreg] = fnHookFunc;
	LeaveCriticalSection(&CritSection);

	DWORD dwPid = GetCurrentProcessId();
	THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == dwPid) {
				if (te.th32ThreadID == GetCurrentThreadId()) {
					continue;
				}

				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (hThread) {
					SuspendThread(hThread);
					CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };

					if (GetThreadContext(hThread, &ctx)) {
						switch (tempDRreg) {
						case Dr0: ctx.Dr0 = (DWORD64)pAddress; ctx.Dr7 |= (1UL << (tempDRreg * 2)); break;
						case Dr1: ctx.Dr1 = (DWORD64)pAddress; ctx.Dr7 |= (1UL << (tempDRreg * 2)); break;
						case Dr2: ctx.Dr2 = (DWORD64)pAddress; ctx.Dr7 |= (1UL << (tempDRreg * 2)); break;
						case Dr3: ctx.Dr3 = (DWORD64)pAddress; ctx.Dr7 |= (1UL << (tempDRreg * 2)); break;
						}
						ctx.Dr7 &= ~(0xFUL << (16 + tempDRreg * 4));

						SetThreadContext(hThread, &ctx);
					}
					ResumeThread(hThread);
					CloseHandle(hThread);
				}
			}
		} while (Thread32Next(hSnapshot, &te));
	}
	CloseHandle(hSnapshot);
	return TRUE;
}

BOOL RemHardBp(IN enum DRreg tempDRreg) {
	if (VEHexceptionHandler == NULL) return FALSE;

	DWORD dwPid = GetCurrentProcessId();
	THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == dwPid) {

				if (te.th32ThreadID == GetCurrentThreadId()) {
					continue;
				}

				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (hThread) {
					SuspendThread(hThread);
					CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };

					if (GetThreadContext(hThread, &ctx)) {
						switch (tempDRreg) {
						case Dr0: ctx.Dr0 = 0x00; break;
						case Dr1: ctx.Dr1 = 0x00; break;
						case Dr2: ctx.Dr2 = 0x00; break;
						case Dr3: ctx.Dr3 = 0x00; break;
						}
						ctx.Dr7 &= ~(3UL << (tempDRreg * 2));
						ctx.Dr7 &= ~(0xFUL << (16 + tempDRreg * 4));

						SetThreadContext(hThread, &ctx);
					}
					ResumeThread(hThread);
					CloseHandle(hThread);
				}
			}
		} while (Thread32Next(hSnapshot, &te));
	}
	CloseHandle(hSnapshot);
	return TRUE;
}

LONG WINAPI VEHfunction(PEXCEPTION_POINTERS pExceptionInfo) {

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

		enum DRreg tempDRreg = -1;
		VOID(*fnHookFunc)(PCONTEXT) = NULL;

		if (pExceptionInfo->ContextRecord->Dr0 == (DWORD64)pExceptionInfo->ExceptionRecord->ExceptionAddress) tempDRreg = Dr0;
		else if (pExceptionInfo->ContextRecord->Dr1 == (DWORD64)pExceptionInfo->ExceptionRecord->ExceptionAddress) tempDRreg = Dr1;
		else if (pExceptionInfo->ContextRecord->Dr2 == (DWORD64)pExceptionInfo->ExceptionRecord->ExceptionAddress) tempDRreg = Dr2;
		else if (pExceptionInfo->ContextRecord->Dr3 == (DWORD64)pExceptionInfo->ExceptionRecord->ExceptionAddress) tempDRreg = Dr3;

		if (tempDRreg != -1) {
			__try {
				EnterCriticalSection(&CritSection);

				if (GlobalBounce[tempDRreg] != TRUE) {
					GlobalBounce[tempDRreg] = TRUE;

					fnHookFunc = pBounceFunction[tempDRreg];
					if (fnHookFunc) {
						fnHookFunc(pExceptionInfo->ContextRecord);
					}
				}

				pExceptionInfo->ContextRecord->EFlags |= (1 << 16);

			}
			__finally {
				LeaveCriticalSection(&CritSection);
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
