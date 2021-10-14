
#include "Config.h"
#include "WndProc.h"
#include <fstream>
#include <string>
#include "threads.h"
#include "protection.h"
#include "image.h"
#include <algorithm>
#include <TlHelp32.h>
#include "Getmac.h"
#include "Runtime Brocer.h"
#include "ObRegisterCallbacks.h"

#include "Antidebug.h"
#include <winternl.h>
#include <intrin.h>
#include <thread>
#include <intrin.h>


// DirectX
#include <d3d9.h>
#include <d3dx9.h>
#include <Psapi.h>
#include <ddraw.h>

using namespace std;

#pragma comment(lib,"d3d9.lib")
#pragma comment(lib,"d3dx9.lib")

#pragma comment(lib,"ntdll.lib")

static string loader_ver = "0";
#define get_array_size(array)	(sizeof(array) / sizeof(array[0]))

////////////////////

DWORD GetProcId(const char* procname)
{
	PROCESSENTRY32 pe;
	HANDLE hSnap;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnap, &pe)) {
		do {
			if (strcmp(pe.szExeFile, procname) == 0)
				break;
		} while (Process32Next(hSnap, &pe));
	}
	return pe.th32ProcessID;
}

/////////////////////////////////////

////////////////////////////////////////////
bool isProcessRun(char* processName)
{
	HANDLE hSnap = NULL;
	PROCESSENTRY32 pe32;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != NULL)
	{
		if (Process32First(hSnap, &pe32))
		{
			if (strcmp(pe32.szExeFile, processName) == 0)
				return TRUE;
			while (Process32Next(hSnap, &pe32))
				if (strcmp(pe32.szExeFile, processName) == 0)
					return TRUE;
		}
	}
	CloseHandle(hSnap);
	return FALSE;
}


BOOL TerminateMyProcess(DWORD dwProcessId, UINT uExitCode);


BOOL TerminateMyProcess(DWORD dwProcessId, UINT uExitCode)
{
	DWORD dwDesiredAccess = PROCESS_TERMINATE;
	BOOL  bInheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	BOOL result = TerminateProcess(hProcess, uExitCode);

	CloseHandle(hProcess);

	return result;
}

BOOL SelfDelete()
{

	TCHAR szFile[MAX_PATH], szCmd[MAX_PATH];

	if ((GetModuleFileName(0, szFile, MAX_PATH) != 0) &&
		(GetShortPathName(szFile, szFile, MAX_PATH) != 0))
	{
		lstrcpy(szCmd, "/c del ");
		lstrcat(szCmd, szFile);
		lstrcat(szCmd, " >> NUL");

		if ((GetEnvironmentVariable("ComSpec", szFile, MAX_PATH) != 0) &&
			((INT)ShellExecute(0, 0, szFile, szCmd, 0, SW_HIDE) > 32))

			return TRUE;
	}
	return FALSE;
}



bool WriteToFile(const char* szFilePath, const char* pBytes, size_t size)
{
	ofstream file(szFilePath, ios::binary);
	if (!file.is_open()) return false;
	file.write(pBytes, size);
	file.close();
	return true;
}

void meme()
{
	OutputDebugStringA;
	(
		TEXT("%s%s%s%s%s%s%s%s%s%s%s")
		TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s")
		TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s")
		TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s"));
	FARPROC Address = GetProcAddress(GetModuleHandle("kernel32.dll"), "ExitProcess");
	if (*(BYTE*)Address == 0xE9 || *(BYTE*)Address == 0x90 || *(BYTE*)Address == 0xC3)
	{
		return;
	}
	adbg_CheckRemoteDebuggerPresent();
	adbg_IsDebuggerPresent();
	adbg_NtQueryInformationProcess();
	adbg_NtSetInformationThread();
	adbg_HardwareDebugRegisters();
	adbg_CloseHandleException();
	hide();
	is();
	is_dbg3;


	if (IsHTTPDebuggerInstalled()) {
		
		exit(0);
	}

	if (IsVMRunning()) {
		exit(EXIT_SUCCESS);
	}


	HideThread();
}



void random_str(char* str, uint32_t len)
{
	constexpr char	charset[] =
	{
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	};
	for (uint32_t i = 0; i < len - 1; ++str, ++i)
	{
		*str = charset[rand() % ((get_array_size(charset) - 1))];
	}

	*(++str) = '\0';
}


void to_clipboard(const char* text)
{
	if (OpenClipboard(0))
	{
		EmptyClipboard();

		char* clip_data = (char*)(GlobalAlloc(GMEM_FIXED, MAX_PATH));
		lstrcpy(clip_data, text);
		SetClipboardData(CF_TEXT, (HANDLE)(clip_data));
		LCID* lcid = (DWORD*)(GlobalAlloc(GMEM_FIXED, sizeof(DWORD)));
		*lcid = MAKELCID(MAKELANGID(LANG_RUSSIAN, SUBLANG_NEUTRAL), SORT_DEFAULT);
		SetClipboardData(CF_LOCALE, (HANDLE)(lcid));

		CloseClipboard();
	}
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplDX9_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	ImGuiIO& io = ImGui::GetIO(); (void)io;
	switch (msg)
	{
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			ImGui_ImplDX9_InvalidateDeviceObjects();
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
			if (hr == D3DERR_INVALIDCALL)
				IM_ASSERT(0);
			ImGui_ImplDX9_CreateDeviceObjects();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU)
			return 0;
		break;
	case WM_DESTROY:
		::PostQuitMessage(0);
		return 0;
	case WM_CHAR:
		wchar_t wch;
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (char*)&wParam, 1, &wch, 1);
		io.AddInputCharacter(wch);
	}
	return ::DefWindowProc(hWnd, msg, wParam, lParam);
}

void init_styles(ImGuiStyle& style) {

	style.WindowPadding = ImVec2(0.000000f, 0.000000f);
	style.FramePadding = ImVec2(0.000000f, 3.000000f);
	style.ItemSpacing = ImVec2(8.000000f, 4.000000f);
	style.ItemInnerSpacing = ImVec2(4.000000f, 4.000000f);
	style.IndentSpacing = 21.000000f;
	style.ScrollbarSize = 1.000000f;
	style.GrabMinSize = 1.000000f;
	style.WindowRounding = 0.000000f;
	style.FrameRounding = 0.000000f;
	style.ScrollbarRounding = 0.000000f;
	style.GrabRounding = 0.000000f;
	style.WindowTitleAlign = ImVec2(0.000000f, 0.500000f);
	style.ButtonTextAlign = ImVec2(0.500000f, 0.500000f);

	style.Colors[ImGuiCol_Text] = ImVec4(0.900000f, 0.900000f, 0.900000f, 1.000000f);
	style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.600000f, 0.600000f, 0.600000f, 1.000000f);
	style.Colors[ImGuiCol_WindowBg] = ImVec4(0.109804f, 0.129412f, 0.152941f, 1.000000f);
	style.Colors[ImGuiCol_PopupBg] = ImVec4(120 / 255.f, 120 / 255.f, 120 / 255.f, 0.300000f);
	style.Colors[ImGuiCol_Border] = ImVec4(0.500000f, 0.500000f, 0.500000f, 0.500000f);
	style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.000000f, 0.000000f, 0.000000f, 0.000000f);
	style.Colors[ImGuiCol_FrameBg] = ImVec4(0.430000f, 0.430000f, 0.430000f, 0.390000f);
	style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.470000f, 0.470000f, 0.690000f, 0.400000f);
	style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.420000f, 0.410000f, 0.640000f, 0.690000f);
	style.Colors[ImGuiCol_TitleBg] = ImVec4(0.270000f, 0.270000f, 0.540000f, 0.830000f);
	style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.320000f, 0.320000f, 0.630000f, 0.870000f);
	style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.400000f, 0.400000f, 0.800000f, 0.200000f);
	style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.400000f, 0.400000f, 0.550000f, 0.800000f);
	style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.200000f, 0.250000f, 0.300000f, 0.600000f);
	style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.400000f, 0.400000f, 0.800000f, 0.300000f);
	style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.400000f, 0.400000f, 0.800000f, 0.400000f);
	style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.410000f, 0.390000f, 0.800000f, 0.600000f);
	style.Colors[ImGuiCol_CheckMark] = ImVec4(0.900000f, 0.900000f, 0.900000f, 0.500000f);
	style.Colors[ImGuiCol_SliderGrab] = ImVec4(1.000000f, 1.000000f, 1.000000f, 0.300000f);
	style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.410000f, 0.390000f, 0.800000f, 0.600000f);
	style.Colors[ImGuiCol_Button] = ImVec4(0.350000f, 0.400000f, 0.610000f, 0.620000f);
	style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.400000f, 0.480000f, 0.710000f, 0.790000f);
	style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.460000f, 0.540000f, 0.800000f, 1.000000f);
	style.Colors[ImGuiCol_Header] = ImVec4(120 / 255.f, 120 / 255.f, 120 / 255.f, 0.300000f);
	style.Colors[ImGuiCol_HeaderHovered] = ImVec4(120 / 255.f, 120 / 255.f, 120 / 255.f, 0.300000f);
	style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.530000f, 0.530000f, 0.870000f, 0.000000f);
	style.Colors[ImGuiCol_ResizeGrip] = ImVec4(1.000000f, 1.000000f, 1.000000f, 0.160000f);
	style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.780000f, 0.820000f, 1.000000f, 0.600000f);
	style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.780000f, 0.820000f, 1.000000f, 0.900000f);
	style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.000000f, 0.000000f, 1.000000f, 0.350000f);
}

int check_version(HINSTANCE hInstance)
{
	OBF_BEGIN
		HideThread(NULL);

	RETURN(1);
	OBF_END

		std::string UrlRequestVer = PATH;
	UrlRequestVer.append(XORSTR("load/lic.php?link=checkvers&ver=") + loader_ver);
	std::string ReciveHash = GetUrlData(UrlRequestVer);


	OBF_BEGIN

		IF(ReciveHash == XORSTR("getupdate"))
	{

		{
			//MessageBox(0, XORSTR("Обновите приложение с группы"), 0, 0);
			///*SelfDelete();*/
			//exit(0);
		}

	}
	ENDIF

		RETURN(1);
	OBF_END
}

extern char  key_buf[512] = ("");
extern char email_buf[512] = ("");


char* getMAC();


char* getMAC() {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return NULL; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return NULL;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// technically should look at pAdapterInfo->AddressLength
			//   and not assume it is 6.
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
			// print them all, return the last one.
			// return mac_addr;

			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);

	return mac_addr;
}

string hwid;
bool statttt = false;
int tyu = 0;

static bool loading_start = false;
static float loading_size = 0.f;
static float loading_volume = 0.f;

int render_base_window()
{
	DWORD dwFlag = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoTitleBar;

	static int i_page = 13;
	static int have_lic = 0;

	OBF_BEGIN

		ImGui::Begin(XORSTR(""), static_cast<bool>(false), ImVec2(WINDOW_WIDTH, WINDOW_HEIGHT), 1.0f, dwFlag);
	{
		auto pos = ImGui::GetWindowPos();
		auto draw = ImGui::GetWindowDrawList();

		draw->AddRectFilled(pos, ImVec2(pos.x + 500, pos.y + 3), ImColor(0, 119, 224));



		IF(V_(have_lic) == N_(0))
		{

			ImGui::SetCursorPos(ImVec2(155, 70));
			std::string key;
			ImGui::BeginGroup();



			ImGui::PushItemWidth(190);
			ImGui::InputText(XORSTR(u8"Login##Login"), login_buf, IM_ARRAYSIZE(login_buf), ImGuiInputTextFlags_AutoSelectAll);
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::InputText(XORSTR(u8"PWD##Password"), password_buf, IM_ARRAYSIZE(password_buf), ImGuiInputTextFlags_Password);
			ImGui::Spacing();


			for (int i = 0; i < 2; i++)
				ImGui::Spacing();

			static std::string ret;

			if (ImGui::Button(XORSTR(u8"Reg"), ImVec2(90, 25)))
			{
				V_(have_lic) = N_(2);

			}

			ImGui::SameLine();
			if (ImGui::Button(XORSTR(u8"Enter"), ImVec2(90, 25)))
			{



				string mac;
				mac += getMAC();

				std::string loginstr;
				std::string passwordstr;
				loginstr += login_buf;
				passwordstr += password_buf;

				std::string UrlRequest = PATH;
				std::string votefack = random_string();
				UrlRequest.append(XORSTR("check/lic.php?login=") + loginstr + XORSTR("&hwid=") + getFirstHddSerialNumber().c_str() + XORSTR("&password=") + passwordstr + XORSTR("&VTF=") + votefack + XORSTR("&mac=") + mac);
				std::string ReciveHash = GetUrlData(UrlRequest);
				std::string dfsdf = xor_decode(ReciveHash, votefack);
				IF(dfsdf == XORSTR("dsfdsfdsf")) 
				{

					loading_start = true;
				}
				ENDIF
					IF(dfsdf == XORSTR("sdfrefdsf"))
				{

					V_(have_lic) = N_(0);
					MessageBox(0, XORSTR("Pwd error"), 0, 0);
				}
				ENDIF
					IF(ReciveHash == XORSTR("hwiderror"))
				{

					V_(have_lic) = N_(0);
					MessageBox(0, XORSTR("Hwid error"), 0, 0);
				}
				ENDIF
					IF(ReciveHash == XORSTR("loginerror"))
				{

					V_(have_lic) = N_(0);
					MessageBox(0, XORSTR("Data error"), 0, 0);
				}
				ENDIF

					ret = dfsdf;
			}
			if (ImGui::Button(XORSTR(u8"Exit"), ImVec2(90, 25)))
				exit(0);
			ImGui::SameLine();

		}
		ImGui::EndGroup();

		ENDIF
			IF(V_(have_lic) == N_(1))
		{

			OBFUSCATED_CALL0(meme);
			ImGui::SameLine();

			if (ImGui::Button(XORSTR(u8"ОClearing Windows logs"), ImVec2(155, 30)))
			{
				system("FOR /F tokens = * %%G in ('wevtutil.exe el') DO (call :do_clear % %G)");
				{
					RETURN(0);
				}
			}
			if (ImGui::Button(XORSTR(u8"Delete Downloads"), ImVec2(155, 30)))
			{


				system("cd %userprofile% && del /q/f/s Downloads");
				{
					MessageBox(NULL, XORSTR("Готово"), XORSTR("Loader"), MB_OK | MB_ICONERROR);
					RETURN(0);
				}


			}
			ImGui::SameLine();
			if (ImGui::Button(XORSTR(u8"Clear Reg"), ImVec2(155, 30)))
			{
				RegDeleteKey(HKEY_CURRENT_USER, "SOFTWARE\\\\MyKey\\\\MyApp");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\\\Classes\\Local Settings\\\\Software\\\\Microsoft\\Windows\\Shell\\MuiCache");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\BagMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Bags");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\FirstFolder");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications");
				system XORSTR("REG DELETE 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Search\RecentApps' /f");
				system XORSTR("REG ADD 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'");
				system XORSTR("REG DELETE 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' /va /f");
				system XORSTR("REG DELETE 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2' /f");
				system XORSTR("REG DELETE  'HKEY_USERS\ % usersid % \Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' /va /f");
				system XORSTR("REG ADD 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'");
				system XORSTR("DEL /f /q %APPDATA%\Microsoft\Windows\Recent\*.*");
				system XORSTR("DEL /f /q %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.*");
				system XORSTR("DEL /f /q %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.*");
				system XORSTR("DEL /f /q %systemroot%\Panther\*.*");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\*.txt");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\*.xml");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\Install\*.txt");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\Install\*.xml");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.pf");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.ini");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.7db");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.ebd");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.bin");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.db");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\ReadyBoot\*.fx");
				system XORSTR("DEL /f /q %systemroot%\Minidump\*.*");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.ini");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.amc");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.mgn");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.lua");


				RETURN(0);

			}
			if (ImGui::Button(XORSTR(u8"Delete Recent"), ImVec2(155, 30)))
			{
				system("cd &AppData% && del /q/f/s \\Microsoft\\Windows\\Recent ");
				{

					RETURN(0);
				}
			}

			if (ImGui::Button(XORSTR(u8"Clear USB DEVICE"), ImVec2(155, 30)))
			{

				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet002\\Enum\\USBSTOR");



				RETURN(0);


			}

			ImGui::SameLine();
			if (ImGui::Button(XORSTR(u8"Delete TEMP"), ImVec2(155, 30)))
			{
				system("del /q/f/s %temp%\\");


				RETURN(0);

			}
			if (ImGui::Button(XORSTR(u8"Delte programm"), ImVec2(155, 30)))
			{
				SelfDelete();
				exit(0);



				RETURN(0);

			}




			ImGui::EndGroup();

		}ENDIF

	}


	ImGui::End();

	RETURN(1);
	OBF_END
}




////////////////////////Инициализация драйверного антидебагера///////////////////////////////////////////


volatile bool endProgram = false;


void checkPEB()
{

	PBOOLEAN BeingDebugged = (PBOOLEAN)__readgsqword(0x60) + 2;


	if (*BeingDebugged)
	{
		exit(0);
		endProgram = true;
	}

}
void    checkHeapFlags()
{
	PVOID       PEBpointer = (PVOID)__readgsqword(0x60);

	DWORD64     processHeap = *(PDWORD64)((DWORD64)PEBpointer + 0x30);


	ULONG       heapFlags = *(ULONG*)((DWORD64)processHeap + 0x70);
	ULONG       heapForceFlags = *(ULONG*)((DWORD64)processHeap + 0x74);

	if (heapFlags & ~HEAP_GROWABLE)
	{
		endProgram = true;
		exit(0);
	}

	if (heapForceFlags != 0)
	{
		endProgram = true;
		exit(0);
	}
}

void NTAPI TLSEntry(PVOID DllHandle, DWORD dwReason, PVOID)
{

	HANDLE DebugPort = NULL;

	checkPEB();

	if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(HANDLE), NULL) == 0)
	{
		if (DebugPort)
		{
			endProgram = true;
			exit(0);
		}
	}

	checkHeapFlags();
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback")
#else
#endif

#ifdef _WIN64
#pragma const_seg(".CRT$XLB")
EXTERN_C const
#else
#endif
PIMAGE_TLS_CALLBACK tls_callback = TLSEntry;
#ifdef _WIN64
#pragma const_seg()
#else
#endif //_WIN64

int antiDebugThread()
{
	BOOL     is_debugger_present = FALSE;
	HANDLE   DebugPort = NULL;


	while (endProgram != true)
	{
		is_debugger_present = IsDebuggerPresent();

		checkHeapFlags();


		if (is_debugger_present != FALSE)
		{
			exit(0);
			endProgram = true;
		}
		Sleep(10);


		if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(HANDLE), NULL) == 0)
		{
			if (DebugPort)
			{
				exit(0);
				endProgram = true;
			}
			Sleep(10);
		}




		if (endProgram == true)
		{
			break;
		}
	}
	return 0;
}



///////////////////////////////////////////////////////////////////





INT __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	PSTR lpCmdLine, INT nCmdShow)
{
	WriteToFile("C:\\Windows\\System32\\drivers\\ee.sys", (const char*)Antidebug, 14888);
	if (system(NULL))
		system XORSTR("sc create ET binPath=C:\\Windows\\System32\\drivers\\ee.sys type= kernel");
	system XORSTR("sc start ET");
	Sleep(5000);
	system XORSTR("sc delete ET");
	remove XORSTR("C:\\Windows\\System32\\drivers\\ee.sys");
	driverHandle = initialize("\\\\.\\antiDebugDevice");



	protectProcess(GetCurrentProcessId());
	std::thread   antiDebugLoop(antiDebugThread);

	protectThreads(GetCurrentProcessId());
	Sleep(10);


	OBF_BEGIN

		int ver = 3.0;
	OBFUSCATED_CALL_RET(int, check_version, hInstance);

	IF(ver)
	{
		char	class_name[0x21] = {};
		random_str(class_name, 0x20);

		WNDCLASSEX wc = WNDCLASSEX{};
		ZeroMemory(&wc, sizeof(wc));

		ImGui::CreateContext();

		wc.cbSize = sizeof(WNDCLASSEX);
		wc.style = CS_HREDRAW | CS_VREDRAW;
		wc.lpfnWndProc = WndProc;
		wc.cbClsExtra = NULL;
		wc.cbWndExtra = NULL;
		wc.hInstance = hInstance;
		wc.lpszMenuName = NULL;
		wc.lpszClassName = class_name;
		wc.hbrBackground = NULL;

		RECT screen_rect;
		GetWindowRect(GetDesktopWindow(), &screen_rect);

		int w = WINDOW_WIDTH,
			h = WINDOW_HEIGHT,
			x = screen_rect.right / 2 - w,
			y = screen_rect.bottom / 2 - h;

		if (auto register_class_ex = RegisterClassExA(&wc))
		{
			if (auto create_window_ex = CreateWindowExA(
				WS_EX_TRANSPARENT,
				class_name,
				class_name,
				WS_POPUP,
				x,
				y,
				w,
				h,
				NULL,
				NULL,
				hInstance,
				NULL))
			{

				if (auto p_d3d = Direct3DCreate9(D3D_SDK_VERSION))
				{
					ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));

					g_d3dpp.Windowed = TRUE;
					g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
					g_d3dpp.hDeviceWindow = create_window_ex;
					g_d3dpp.MultiSampleQuality = D3DMULTISAMPLE_NONE;
					g_d3dpp.BackBufferFormat = D3DFMT_A8R8G8B8;
					g_d3dpp.BackBufferWidth = w;
					g_d3dpp.BackBufferHeight = h;
					g_d3dpp.EnableAutoDepthStencil = TRUE;
					g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
					g_d3dpp.Windowed = TRUE;

					auto hr = p_d3d->CreateDevice(
						D3DADAPTER_DEFAULT,
						D3DDEVTYPE_HAL,
						create_window_ex,
						D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_PUREDEVICE,
						&g_d3dpp,
						&g_pd3dDevice
					);

					if (FAILED(hr))
					{
						hr = p_d3d->CreateDevice(
							D3DADAPTER_DEFAULT,
							D3DDEVTYPE_HAL,
							create_window_ex,
							D3DCREATE_SOFTWARE_VERTEXPROCESSING,
							&g_d3dpp,
							&g_pd3dDevice
						);
					}

					if (FAILED(hr))
					{
						if (g_pd3dDevice)
						{
							g_pd3dDevice->Release();
						}

						if (p_d3d)
						{
							p_d3d->Release();
						}

						UnregisterClassA(class_name, wc.hInstance);

						RETURN(0);
					}
					OBFUSCATED_CALL(ImGui_ImplDX9_Init, create_window_ex, g_pd3dDevice);

					ImGui::GetIO().Fonts->AddFontFromMemoryCompressedTTF(
						myfont_compressed_data,
						myfont_compressed_size,
						18.f,
						nullptr,
						ImGui::GetIO().Fonts->GetGlyphRangesCyrillic());

					ImGuiStyle& style = ImGui::GetStyle();
					init_styles(style);

					ShowWindow(create_window_ex, nCmdShow);
					UpdateWindow(create_window_ex);

					MSG msg = MSG{};
					ZeroMemory(&msg, sizeof(msg));

					WHILE(msg.message != WM_QUIT)
					{
						if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE) > 0)
						{
							TranslateMessage(&msg);
							DispatchMessageA(&msg);
							CONTINUE;
						}

						OBFUSCATED_CALL0(ImGui_ImplDX9_NewFrame);

						OBFUSCATED_CALL_RET0(int, render_base_window);

						OBFUSCATED_CALL0(meme);



						if (g_pd3dDevice->BeginScene() >= 0)
						{
							ImGui::Render();
							g_pd3dDevice->EndScene();
						}

						HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

						if (result == D3DERR_DEVICELOST &&
							g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
						{
							ImGui_ImplDX9_InvalidateDeviceObjects();
							g_pd3dDevice->Reset(&g_d3dpp);
							ImGui_ImplDX9_CreateDeviceObjects();
						}

					}
					ENDWHILE

						OBFUSCATED_CALL0(ImGui_ImplDX9_Shutdown);
					ImGui::DestroyContext((ImGuiContext*)nullptr);

					if (g_pd3dDevice)
					{
						g_pd3dDevice->Release();
					}

					if (p_d3d)
					{
						p_d3d->Release();
					}

					UnregisterClassA(class_name, wc.hInstance);
					RETURN(msg.wParam);
				}

			}
		}

		if (g_pd3dDevice)
		{
			g_pd3dDevice->Release();
		}

		UnregisterClassA(class_name, wc.hInstance);
		RETURN(0);
	}
	ELSE
	{
		RETURN(0);
	}
		ENDIF

		OBF_END
}
//#define LAZY_IMPORTER_CASE_INSENSITIVE 
//#define LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS 
//#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

#include "Config.h"
#include "WndProc.h"
#include <fstream>
#include <string>
#include "threads.h"
#include "protection.h"
#include "image.h"
#include <algorithm>
#include <TlHelp32.h>
#include "Getmac.h"
#include "Runtime Brocer.h"
#include "ObRegisterCallbacks.h"

#include "Antidebug.h"
#include <winternl.h>
#include <intrin.h>
#include <thread>
#include <intrin.h>


// DirectX
#include <d3d9.h>
#include <d3dx9.h>
#include <Psapi.h>
#include <ddraw.h>

using namespace std;

#pragma comment(lib,"d3d9.lib")
#pragma comment(lib,"d3dx9.lib")

#pragma comment(lib,"ntdll.lib")

static string loader_ver = "12";
#define get_array_size(array)	(sizeof(array) / sizeof(array[0]))

////////////////////

DWORD GetProcId(const char* procname)
{
	PROCESSENTRY32 pe;
	HANDLE hSnap;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnap, &pe)) {
		do {
			if (strcmp(pe.szExeFile, procname) == 0)
				break;
		} while (Process32Next(hSnap, &pe));
	}
	return pe.th32ProcessID;
}

/////////////////////////////////////

////////////////////////////////////////////
bool isProcessRun(char* processName)
{
	HANDLE hSnap = NULL;
	PROCESSENTRY32 pe32;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != NULL)
	{
		if (Process32First(hSnap, &pe32))
		{
			if (strcmp(pe32.szExeFile, processName) == 0)
				return TRUE;
			while (Process32Next(hSnap, &pe32))
				if (strcmp(pe32.szExeFile, processName) == 0)
					return TRUE;
		}
	}
	CloseHandle(hSnap);
	return FALSE;
}


BOOL TerminateMyProcess(DWORD dwProcessId, UINT uExitCode);


BOOL TerminateMyProcess(DWORD dwProcessId, UINT uExitCode)
{
	DWORD dwDesiredAccess = PROCESS_TERMINATE;
	BOOL  bInheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	BOOL result = TerminateProcess(hProcess, uExitCode);

	CloseHandle(hProcess);

	return result;
}

BOOL SelfDelete()
{

	TCHAR szFile[MAX_PATH], szCmd[MAX_PATH];

	if ((GetModuleFileName(0, szFile, MAX_PATH) != 0) &&
		(GetShortPathName(szFile, szFile, MAX_PATH) != 0))
	{
		lstrcpy(szCmd, "/c del ");
		lstrcat(szCmd, szFile);
		lstrcat(szCmd, " >> NUL");

		if ((GetEnvironmentVariable("ComSpec", szFile, MAX_PATH) != 0) &&
			((INT)ShellExecute(0, 0, szFile, szCmd, 0, SW_HIDE) > 32))

			return TRUE;
	}
	return FALSE;
}



bool WriteToFile(const char* szFilePath, const char* pBytes, size_t size)
{
	ofstream file(szFilePath, ios::binary);
	if (!file.is_open()) return false;
	file.write(pBytes, size);
	file.close();
	return true;
}

void meme()
{
	OutputDebugStringA;
	(
		TEXT("%s%s%s%s%s%s%s%s%s%s%s")
		TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s")
		TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s")
		TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s"));
	FARPROC Address = GetProcAddress(GetModuleHandle("kernel32.dll"), "ExitProcess");
	if (*(BYTE*)Address == 0xE9 || *(BYTE*)Address == 0x90 || *(BYTE*)Address == 0xC3)
	{
		return;
	}
	adbg_CheckRemoteDebuggerPresent();
	adbg_IsDebuggerPresent();
	adbg_NtQueryInformationProcess();
	adbg_NtSetInformationThread();
	adbg_HardwareDebugRegisters();
	adbg_CloseHandleException();
	hide();
	is();
	is_dbg3;


	if (IsHTTPDebuggerInstalled()) {
		exit(0);
	}

	if (IsVMRunning()) {
		exit(EXIT_SUCCESS);
	}


	HideThread();
}



void random_str(char* str, uint32_t len)
{
	constexpr char	charset[] =
	{
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	};
	for (uint32_t i = 0; i < len - 1; ++str, ++i)
	{
		*str = charset[rand() % ((get_array_size(charset) - 1))];
	}

	*(++str) = '\0';
}


void to_clipboard(const char* text)
{
	if (OpenClipboard(0))
	{
		EmptyClipboard();

		char* clip_data = (char*)(GlobalAlloc(GMEM_FIXED, MAX_PATH));
		lstrcpy(clip_data, text);
		SetClipboardData(CF_TEXT, (HANDLE)(clip_data));
		LCID* lcid = (DWORD*)(GlobalAlloc(GMEM_FIXED, sizeof(DWORD)));
		*lcid = MAKELCID(MAKELANGID(LANG_RUSSIAN, SUBLANG_NEUTRAL), SORT_DEFAULT);
		SetClipboardData(CF_LOCALE, (HANDLE)(lcid));

		CloseClipboard();
	}
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplDX9_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	ImGuiIO& io = ImGui::GetIO(); (void)io;
	switch (msg)
	{
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			ImGui_ImplDX9_InvalidateDeviceObjects();
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
			if (hr == D3DERR_INVALIDCALL)
				IM_ASSERT(0);
			ImGui_ImplDX9_CreateDeviceObjects();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU)
			return 0;
		break;
	case WM_DESTROY:
		::PostQuitMessage(0);
		return 0;
	case WM_CHAR:
		wchar_t wch;
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (char*)&wParam, 1, &wch, 1);
		io.AddInputCharacter(wch);
	}
	return ::DefWindowProc(hWnd, msg, wParam, lParam);
}

void init_styles(ImGuiStyle& style) {

	//Constants for imgui
}

int check_version(HINSTANCE hInstance)
{
	OBF_BEGIN
		HideThread(NULL);

	RETURN(1);
	OBF_END

		std::string UrlRequestVer = PATH;
	UrlRequestVer.append(XORSTR("load/lic.php?link=checkvers&ver=") + loader_ver);
	std::string ReciveHash = GetUrlData(UrlRequestVer);


	OBF_BEGIN

	IF(ReciveHash == XORSTR("getupdate"))
	{

		{
		
			SelfDelete();
			exit(0);
		}

	}
	ENDIF

		RETURN(1);
	OBF_END
}

extern char  key_buf[512] = ("");
extern char email_buf[512] = ("");


char* getMAC();


char* getMAC() {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return NULL; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return NULL;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// technically should look at pAdapterInfo->AddressLength
			//   and not assume it is 6.
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
			// print them all, return the last one.
			// return mac_addr;

			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);

	return mac_addr;
}

string hwid;
bool statttt = false;
int tyu = 0;

static bool loading_start = false;
static float loading_size = 0.f;
static float loading_volume = 0.f;

int render_base_window()
{
	DWORD dwFlag = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoTitleBar;

	static int i_page = 13;
	static int have_lic = 0;

	OBF_BEGIN

	ImGui::Begin(XORSTR(""), static_cast<bool>(false), ImVec2(WINDOW_WIDTH, WINDOW_HEIGHT), 1.0f, dwFlag);
	{
		auto pos = ImGui::GetWindowPos();
		auto draw = ImGui::GetWindowDrawList();

		draw->AddRectFilled(pos, ImVec2(pos.x + 500, pos.y + 3), ImColor(0, 119, 224));



		IF(V_(have_lic) == N_(0))
		{

			ImGui::SetCursorPos(ImVec2(155, 70));
			std::string key;
			ImGui::BeginGroup();



			ImGui::PushItemWidth(190);
			ImGui::InputText(XORSTR(u8"Login##Login"), login_buf, IM_ARRAYSIZE(login_buf), ImGuiInputTextFlags_AutoSelectAll);
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::Spacing();
			ImGui::InputText(XORSTR(u8"PWD##Password"), password_buf, IM_ARRAYSIZE(password_buf), ImGuiInputTextFlags_Password);
			ImGui::Spacing();


			for (int i = 0; i < 2; i++)
				ImGui::Spacing();

			static std::string ret;

			if (ImGui::Button(XORSTR(u8"Reg"), ImVec2(90, 25)))
			{
				V_(have_lic) = N_(2);

			}

			ImGui::SameLine();
			if (ImGui::Button(XORSTR(u8"Enter"), ImVec2(90, 25)))
			{



				string mac;
				mac += getMAC();

				std::string loginstr;
				std::string passwordstr;
				loginstr += login_buf;
				passwordstr += password_buf;

				std::string UrlRequest = PATH;
				std::string votefack = random_string();
				UrlRequest.append(XORSTR("check/lic.php?login=") + loginstr + XORSTR("&hwid=") + getFirstHddSerialNumber().c_str() + XORSTR("&password=") + passwordstr + XORSTR("&VTF=") + votefack + XORSTR("&mac=") + mac);
				std::string ReciveHash = GetUrlData(UrlRequest);
				std::string dfsdf = xor_decode(ReciveHash, votefack);
				IF(dfsdf == XORSTR("dsfdsfdsf")) 
				{

					loading_start = true;
				}
				ENDIF
					IF(dfsdf == XORSTR("sdfrefdsf"))
				{

					V_(have_lic) = N_(0);
					MessageBox(0, XORSTR("Pwd error"), 0, 0);
				}
				ENDIF
					IF(ReciveHash == XORSTR("hwiderror"))
				{

					V_(have_lic) = N_(0);
					MessageBox(0, XORSTR("Hwid error"), 0, 0);
				}
				ENDIF
					IF(ReciveHash == XORSTR("loginerror"))
				{

					V_(have_lic) = N_(0);
					MessageBox(0, XORSTR("Data error"), 0, 0);
				}
				ENDIF

					ret = dfsdf;
			}
			if (ImGui::Button(XORSTR(u8"Exit"), ImVec2(90, 25)))
				exit(0);
			ImGui::SameLine();

		}
		ImGui::EndGroup();

		ENDIF
			IF(V_(have_lic) == N_(1))
		{

			OBFUSCATED_CALL0(meme);
			ImGui::SameLine();

			if (ImGui::Button(XORSTR(u8"ОClearing Windows logs"), ImVec2(155, 30)))
			{
				system("FOR /F tokens = * %%G in ('wevtutil.exe el') DO (call :do_clear % %G)");
				{
					RETURN(0);
				}
			}
			if (ImGui::Button(XORSTR(u8"Delete Downloads"), ImVec2(155, 30)))
			{


				system("cd %userprofile% && del /q/f/s Downloads");
				{
					MessageBox(NULL, XORSTR("Готово"), XORSTR("Loader"), MB_OK | MB_ICONERROR);
					RETURN(0);
				}


			}
			ImGui::SameLine();
			if (ImGui::Button(XORSTR(u8"Clear Reg"), ImVec2(155, 30)))
			{
				RegDeleteKey(HKEY_CURRENT_USER, "SOFTWARE\\\\MyKey\\\\MyApp");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\\\Classes\\Local Settings\\\\Software\\\\Microsoft\\Windows\\Shell\\MuiCache");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\BagMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Bags");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\FirstFolder");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU");
				RegDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications");
				system XORSTR("REG DELETE 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Search\RecentApps' /f");
				system XORSTR("REG ADD 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'");
				system XORSTR("REG DELETE 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' /va /f");
				system XORSTR("REG DELETE 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2' /f");
				system XORSTR("REG DELETE  'HKEY_USERS\ % usersid % \Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' /va /f");
				system XORSTR("REG ADD 'HKEY_USERS\ % usersid % \Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'");
				system XORSTR("DEL /f /q %APPDATA%\Microsoft\Windows\Recent\*.*");
				system XORSTR("DEL /f /q %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.*");
				system XORSTR("DEL /f /q %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.*");
				system XORSTR("DEL /f /q %systemroot%\Panther\*.*");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\*.txt");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\*.xml");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\Install\*.txt");
				system XORSTR("DEL /f /q %systemroot%\appcompat\Programs\Install\*.xml");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.pf");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.ini");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.7db");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.ebd");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.bin");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.db");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\ReadyBoot\*.fx");
				system XORSTR("DEL /f /q %systemroot%\Minidump\*.*");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.ini");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.amc");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.mgn");
				system XORSTR("DEL /f /q %systemroot%\Prefetch\*.lua");


				RETURN(0);

			}
			if (ImGui::Button(XORSTR(u8"Delete Recent"), ImVec2(155, 30)))
			{
				system("cd &AppData% && del /q/f/s \\Microsoft\\Windows\\Recent ");
				{

					RETURN(0);
				}
			}

			if (ImGui::Button(XORSTR(u8"Clear USB DEVICE"), ImVec2(155, 30)))
			{

				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR");
				RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet002\\Enum\\USBSTOR");



				RETURN(0);


			}

			ImGui::SameLine();
			if (ImGui::Button(XORSTR(u8"Delete TEMP"), ImVec2(155, 30)))
			{
				system("del /q/f/s %temp%\\");


				RETURN(0);

			}
			if (ImGui::Button(XORSTR(u8"Delte programm"), ImVec2(155, 30)))
			{
				SelfDelete();
				exit(0);



				RETURN(0);

			}




			ImGui::EndGroup();

		}ENDIF

	}


	ImGui::End();

	RETURN(1);
	OBF_END
}




////////////////////////Инициализация драйверного антидебагера///////////////////////////////////////////


volatile bool endProgram = false;


void checkPEB()
{

	PBOOLEAN BeingDebugged = (PBOOLEAN)__readgsqword(0x60) + 2;


	if (*BeingDebugged)
	{
		exit(0);
		endProgram = true;
	}

}
void    checkHeapFlags()
{
	PVOID       PEBpointer = (PVOID)__readgsqword(0x60);

	DWORD64     processHeap = *(PDWORD64)((DWORD64)PEBpointer + 0x30);


	ULONG       heapFlags = *(ULONG*)((DWORD64)processHeap + 0x70);
	ULONG       heapForceFlags = *(ULONG*)((DWORD64)processHeap + 0x74);

	if (heapFlags & ~HEAP_GROWABLE)
	{
		endProgram = true;
		exit(0);
	}

	if (heapForceFlags != 0)
	{
		endProgram = true;
		exit(0);
	}
}

void NTAPI TLSEntry(PVOID DllHandle, DWORD dwReason, PVOID)
{

	HANDLE DebugPort = NULL;

	checkPEB();

	if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(HANDLE), NULL) == 0)
	{
		if (DebugPort)
		{
			endProgram = true;
			exit(0);
		}
	}

	checkHeapFlags();
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback")
#else
#endif

#ifdef _WIN64
#pragma const_seg(".CRT$XLB")
EXTERN_C const
#else
#endif
PIMAGE_TLS_CALLBACK tls_callback = TLSEntry;
#ifdef _WIN64
#pragma const_seg()
#else
#endif //_WIN64

int antiDebugThread()
{
	BOOL     is_debugger_present = FALSE;
	HANDLE   DebugPort = NULL;


	while (endProgram != true)
	{
		is_debugger_present = IsDebuggerPresent();

		checkHeapFlags();


		if (is_debugger_present != FALSE)
		{
			exit(0);
			endProgram = true;
		}
		Sleep(10);


		if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(HANDLE), NULL) == 0)
		{
			if (DebugPort)
			{
				exit(0);
				endProgram = true;
			}
			Sleep(10);
		}




		if (endProgram == true)
		{
			break;
		}
	}
	return 0;
}



///////////////////////////////////////////////////////////////////





INT __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	PSTR lpCmdLine, INT nCmdShow)
{
	WriteToFile("C:\\Windows\\System32\\drivers\\protect.sys", (const char*)Antidebug, 14888);
	if (system(NULL))
		system XORSTR("sc create PR binPath=C:\\Windows\\System32\\drivers\\protect.sys type= kernel");
	system XORSTR("sc start PR");
	Sleep(5000);
	system XORSTR("sc delete PR");
	remove XORSTR("C:\\Windows\\System32\\drivers\\protect.sys");
	driverHandle = initialize("\\\\.\\antiDebugDevice");



	protectProcess(GetCurrentProcessId());
	std::thread   antiDebugLoop(antiDebugThread);

	protectThreads(GetCurrentProcessId());
	Sleep(10);


	OBF_BEGIN

		int ver = 3.0;
	OBFUSCATED_CALL_RET(int, check_version, hInstance);

	IF(ver)
	{
		char	class_name[0x21] = {};
		random_str(class_name, 0x20);

		WNDCLASSEX wc = WNDCLASSEX{};
		ZeroMemory(&wc, sizeof(wc));

		ImGui::CreateContext();

		wc.cbSize = sizeof(WNDCLASSEX);
		wc.style = CS_HREDRAW | CS_VREDRAW;
		wc.lpfnWndProc = WndProc;
		wc.cbClsExtra = NULL;
		wc.cbWndExtra = NULL;
		wc.hInstance = hInstance;
		wc.lpszMenuName = NULL;
		wc.lpszClassName = class_name;
		wc.hbrBackground = NULL;

		RECT screen_rect;
		GetWindowRect(GetDesktopWindow(), &screen_rect);

		int w = WINDOW_WIDTH,
			h = WINDOW_HEIGHT,
			x = screen_rect.right / 2 - w,
			y = screen_rect.bottom / 2 - h;

		if (auto register_class_ex = RegisterClassExA(&wc))
		{
			if (auto create_window_ex = CreateWindowExA(
				WS_EX_TRANSPARENT,
				class_name,
				class_name,
				WS_POPUP,
				x,
				y,
				w,
				h,
				NULL,
				NULL,
				hInstance,
				NULL))
			{

				if (auto p_d3d = Direct3DCreate9(D3D_SDK_VERSION))
				{
					ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));

					g_d3dpp.Windowed = TRUE;
					g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
					g_d3dpp.hDeviceWindow = create_window_ex;
					g_d3dpp.MultiSampleQuality = D3DMULTISAMPLE_NONE;
					g_d3dpp.BackBufferFormat = D3DFMT_A8R8G8B8;
					g_d3dpp.BackBufferWidth = w;
					g_d3dpp.BackBufferHeight = h;
					g_d3dpp.EnableAutoDepthStencil = TRUE;
					g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
					g_d3dpp.Windowed = TRUE;

					auto hr = p_d3d->CreateDevice(
						D3DADAPTER_DEFAULT,
						D3DDEVTYPE_HAL,
						create_window_ex,
						D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_PUREDEVICE,
						&g_d3dpp,
						&g_pd3dDevice
					);

					if (FAILED(hr))
					{
						hr = p_d3d->CreateDevice(
							D3DADAPTER_DEFAULT,
							D3DDEVTYPE_HAL,
							create_window_ex,
							D3DCREATE_SOFTWARE_VERTEXPROCESSING,
							&g_d3dpp,
							&g_pd3dDevice
						);
					}

					if (FAILED(hr))
					{
						if (g_pd3dDevice)
						{
							g_pd3dDevice->Release();
						}

						if (p_d3d)
						{
							p_d3d->Release();
						}

						UnregisterClassA(class_name, wc.hInstance);

						RETURN(0);
					}
					OBFUSCATED_CALL(ImGui_ImplDX9_Init, create_window_ex, g_pd3dDevice);

					ImGui::GetIO().Fonts->AddFontFromMemoryCompressedTTF(
						myfont_compressed_data,
						myfont_compressed_size,
						18.f,
						nullptr,
						ImGui::GetIO().Fonts->GetGlyphRangesCyrillic());

					ImGuiStyle& style = ImGui::GetStyle();
					init_styles(style);

					ShowWindow(create_window_ex, nCmdShow);
					UpdateWindow(create_window_ex);

					MSG msg = MSG{};
					ZeroMemory(&msg, sizeof(msg));

					WHILE(msg.message != WM_QUIT)
					{
						if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE) > 0)
						{
							TranslateMessage(&msg);
							DispatchMessageA(&msg);
							CONTINUE;
						}

						OBFUSCATED_CALL0(ImGui_ImplDX9_NewFrame);

						OBFUSCATED_CALL_RET0(int, render_base_window);

						OBFUSCATED_CALL0(meme);



						if (g_pd3dDevice->BeginScene() >= 0)
						{
							ImGui::Render();
							g_pd3dDevice->EndScene();
						}

						HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

						if (result == D3DERR_DEVICELOST &&
							g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
						{
							ImGui_ImplDX9_InvalidateDeviceObjects();
							g_pd3dDevice->Reset(&g_d3dpp);
							ImGui_ImplDX9_CreateDeviceObjects();
						}

					}
					ENDWHILE

						OBFUSCATED_CALL0(ImGui_ImplDX9_Shutdown);
					ImGui::DestroyContext((ImGuiContext*)nullptr);

					if (g_pd3dDevice)
					{
						g_pd3dDevice->Release();
					}

					if (p_d3d)
					{
						p_d3d->Release();
					}

					UnregisterClassA(class_name, wc.hInstance);
					RETURN(msg.wParam);
				}

			}
		}

		if (g_pd3dDevice)
		{
			g_pd3dDevice->Release();
		}

		UnregisterClassA(class_name, wc.hInstance);
		RETURN(0);
	}
	ELSE
	{
		RETURN(0);
	}
		ENDIF

		OBF_END
}
