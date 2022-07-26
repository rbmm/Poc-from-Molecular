#define WIN32_LEAN_AND_MEAN
#define DECLSPEC_DEPRECATED_DDK

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 0

//#include <stdlib.h>
#include <stdio.h>
//#include <string.h>
#include <windows.h>

EXTERN_C_START

WINBASEAPI
ULONG
__cdecl
DbgPrint (
		  _In_z_ _Printf_format_string_ PCSTR Format,
		  ...
		  );

WINBASEAPI
LONG
NTAPI
RtlGetLastNtStatus();

EXTERN_C_END

SIZE_T GetAllocationGranularity()
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwAllocationGranularity - 1;
}

void CALLBACK ep(void*)
{
	if (PWSTR psz = (PWSTR)LocalAlloc(0, (MAXSHORT + 1) * sizeof(WCHAR)))
	{
		GetModuleFileNameW(0, psz, MAXSHORT + 1);

		if (!GetLastError())
		{
			PROCESS_INFORMATION pi;
			STARTUPINFO si = { sizeof(si) };

			if (CreateProcessW(psz, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
			{
				CloseHandle(pi.hThread);

				MEMORY_BASIC_INFORMATION mbi{};

				SIZE_T a = GetAllocationGranularity(), b = ~a;

				ULONG QueryCount = 1, AllocCount = 0;

				while (VirtualQueryEx(pi.hProcess, mbi.BaseAddress, &mbi, sizeof(mbi)))
				{
					QueryCount++;

					if (mbi.State == MEM_FREE)
					{
						if (SIZE_T dwSize = mbi.RegionSize & b)
						{
							AllocCount++;

							mbi.AllocationBase = (PVOID)(((ULONG_PTR)mbi.BaseAddress + a) & b);

							DbgPrint("(%p, %p) (%p, %p)\n", mbi.BaseAddress, mbi.RegionSize, mbi.AllocationBase, dwSize);

							if (!VirtualAllocEx(pi.hProcess, mbi.AllocationBase, dwSize, MEM_RESERVE, PAGE_NOACCESS))
							{
								DbgPrint("\t!! %x\n", RtlGetLastNtStatus());
							}
						}
					}

					(PBYTE&)mbi.BaseAddress += mbi.RegionSize;
				}

				swprintf_s(psz, MAXSHORT + 1, L"q=%u a=%u", QueryCount, AllocCount);

				if (MessageBox(0, psz, L"Do Hang ?", MB_ICONWARNING|MB_YESNO) == IDYES)
				{
					LONG status = VirtualAllocEx(pi.hProcess, 0, a + 1, MEM_RESERVE, PAGE_NOACCESS) ? 0 : RtlGetLastNtStatus();

					swprintf_s(psz, MAXSHORT + 1, L"va=%x", status);

					MessageBox(0, psz, 0, MB_ICONWARNING);
				}
				
				TerminateProcess(pi.hProcess, 0);

				CloseHandle(pi.hProcess);
			}
		}

		LocalFree(psz);
	}

	ExitProcess(0);
}