
#include"protection.h"



bool HideThread(HANDLE hThread)
{

	typedef NTSTATUS(NTAPI* pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	// Get NtSetInformationThread
	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationThread");

	// Shouldn't fail
	if (NtSIT == NULL)
		return false;

	// Set the thread info
	if (hThread == NULL)
		Status = NtSIT(GetCurrentThread(),
			0x11, // HideThreadFromDebugger
			0, 0);
	else
		Status = NtSIT(hThread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;

}

/*
void hide_from_debugger() {
 
	typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
		_In_ HANDLE ThreadHandle,
		_In_ ULONG  ThreadInformationClass,
		_In_ PVOID  ThreadInformation,
		_In_ ULONG  ThreadInformationLength
		);
	const ULONG ThreadHideFromDebugger = 0x11;

	if (auto lla = LI_FN(LoadLibraryA).forwarded_safe_cached()) {
		if (auto hNtDll = lla("ntdll.dll")) {

			if (auto gpa = LI_FN(GetProcAddress).forwarded_safe_cached()) {
				pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
					gpa(hNtDll, "NtSetInformationThread");
				if (auto gct = LI_FN(GetCurrentThread).forwarded_safe_cached()) {
					NTSTATUS status = NtSetInformationThread(gct(),
						ThreadHideFromDebugger, NULL, 0);
				}
			}
		}
	}
}
*/