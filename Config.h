#include <thread>
#include <mutex>

std::once_flag flag;
#define DO_ONCE(...)  { static bool _do_once_ = ([&](){ __VA_ARGS__ }(), true); (void)_do_once_; }

#include "obfy-master/instr.h"
#include "xor.hpp"
#include "Obfuscate/Lib/MetaString.h"
#include "Obfuscate/Lib/ObfuscatedCall.h"
using namespace andrivet::ADVobfuscator;


#define NAME_LOADER " "

#define WINDOW_WIDTH  500
#define WINDOW_HEIGHT 300

#include <io.h>

#include "Guard.h"


extern bool have_lic = true;

std::string successL;
std::string errorL;
std::string getupdate;




std::string LoginHash(std::string hash)
{
	//GetHashText();
	for (int i = 10; i <= 25; i++)
	{
		successL = XORSTR("dskfksdgk");
		errorL = XORSTR("sdfregegreg");
		getupdate = XORSTR("wqreewrewr");

		if (hash == successL)
			return successL;

		else if (hash == errorL)
			return errorL;
		else if (hash == getupdate)
			return 	getupdate;
	}
	return false;
}
std::string LicL = XORSTR("oerowroewor");
std::string LicE = XORSTR("ksdkfdgjmdfg");

std::string LickHash(std::string hash)
{
	std::string Temp_LicL = LicL.c_str();
	std::string	Temp_LicE = LicE.c_str();
	//base64_encode(LicE.c_str(), static_cast<unsigned int>(LicE.size()));

	if (hash == LicL)
	{
		return Temp_LicL;
	}
	else if (hash == LicE)
	{
		return Temp_LicE;
	}

	return "";
}


std::string xor_decode(std::string data, std::string key)
{
	int g = key.length();
	int r = data.length();
	string ff = "";
	for (int i = 0; i < r; i++)
	{
		ff += data[i] ^= key[i % g];
	}
	return ff;
}

namespace {
	std::string const default_chars =
		"abcdefghijklmnaoqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
}

std::string random_string(size_t len = 10, std::string const& allowed_chars = default_chars) {
	std::mt19937_64 gen{ std::random_device()() };

	std::uniform_int_distribution<size_t> dist{ 0, allowed_chars.length() - 1 };

	std::string ret;

	std::generate_n(std::back_inserter(ret), len, [&] { return allowed_chars[dist(gen)]; });
	return ret;
}

extern char login_buf[32] = ("");
extern char password_buf[64] = (" ");

inline bool CheckLic(std::string game)
{
	OBF_BEGIN
	


	std::string xap = random_string();
	std::string UrlRequest = "/";
	UrlRequest.append(XORSTR("check/lic.php?link=licens&info") + game + XORSTR("&hwid=") + getFirstHddSerialNumber().c_str() + XORSTR("&VTF=") + xap);

	std::string ReciveHash = GetUrlData(UrlRequest);

	std::string fart = xor_decode(ReciveHash, xap);
	auto check = OBFUSCATED_CALL_RET(std::string, LickHash, LicL);

	IF(fart == check)
	{
		RETURN(1);// true;
	}
	ELSE
	{
		RETURN(0);
	}
		ENDIF

		RETURN(0);
	OBF_END
}

extern bool check_access;

void check_license()
{
		if (!CheckLic(XORSTR("lic"))) check_access = 0;
}


void adbg_CheckRemoteDebuggerPresent(void)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	hProcess = GetCurrentProcess();
	CheckRemoteDebuggerPresent(hProcess, &found);

	if (found)
	{
		exit(0);
	}
}

void adbg_IsDebuggerPresent(void)
{
	BOOL found = FALSE;
	found = IsDebuggerPresent();

	if (found)
	{
		exit(0);
	}
}

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
void adbg_NtQueryInformationProcess(void)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	DWORD found = FALSE;
	DWORD ProcessDebugPort = 0x07;	// 1st method; See MSDN for details
	DWORD ProcessDebugFlags = 0x1F;	// 2nd method; See MSDN for details

	// Get a handle to ntdll.dll so we can import NtQueryInformationProcess
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		goto CANT_CHECK;
	}

	// Dynamically acquire the addres of NtQueryInformationProcess
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, XORSTR("NtQueryInformationProcess"));

	if (NtQueryInformationProcess == NULL)
	{
		goto CANT_CHECK;
	}

	// Method 1: Query ProcessDebugPort
	hProcess = GetCurrentProcess();
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &found, sizeof(DWORD), NULL);

	if (!status && found)
	{
		exit(0);
	}

	// Method 2: Query ProcessDebugFlags
	status = NtQueryInformationProcess(hProcess, ProcessDebugFlags, &found, sizeof(DWORD), NULL);

	// The ProcessDebugFlags caused 'found' to be 1 if no debugger is found, so we check !found.
	if (!status && !found)
	{
		exit(0);
	}
	//
CANT_CHECK: NULL;
	//	_asm
	//	{
	//		nop;
	//	}
}

typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);
void adbg_NtSetInformationThread(void)
{
	DWORD ThreadHideFromDebugger = 0x11;

	// Get a handle to ntdll.dll so we can import NtSetInformationThread
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		goto CANT_CHECK;
	}

	// Dynamically acquire the addres of NtSetInformationThread and NtQueryInformationThread
	_NtSetInformationThread NtSetInformationThread = NULL;
	NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, XORSTR("NtSetInformationThread"));

	if (NtSetInformationThread == NULL)
	{
		goto CANT_CHECK;
	}

	// There is nothing to check here after this call.
	NtSetInformationThread(GetCurrentThread(), (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger, 0, 0);

CANT_CHECK: NULL;
}



void adbg_HardwareDebugRegisters(void)
{
	BOOL found = FALSE;
	CONTEXT ctx = { 0 };
	HANDLE hThread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(hThread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = TRUE;
		}
	}

	if (found)
	{
		exit(0);
	}
}

void adbg_CloseHandleException(void)
{
	HANDLE hInvalid = (HANDLE)0xDEADBEEF; // an invalid handle
	DWORD found = FALSE;

	__try
	{
		CloseHandle(hInvalid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		found = TRUE;
	}

	if (found)
	{
		exit(0);
	}
}

