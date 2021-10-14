#pragma once
#include <iostream>
#include <windows.h>
#include <WinUser.h>
#include <WinBase.h>
#include <tchar.h>
#include <urlmon.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib, "Advapi32.lib")

#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>
#include <WinInet.h>
#include <iomanip>
#include <cstdio>  
#include "xor.hpp"
#include <intrin.h>

static const char* B64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int B64index[256] =
{
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
	0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
	0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

const std::string b64encode(const void* data, const size_t& len)
{
	std::string result((len + 2) / 3 * 4, '=');
	char* p = (char*)data, * str = &result[0];
	size_t j = 0, pad = len % 3;
	const size_t last = len - pad;

	for (size_t i = 0; i < last; i += 3)
	{
		int n = int(p[i]) << 16 | int(p[i + 1]) << 8 | p[i + 2];
		str[j++] = B64chars[n >> 18];
		str[j++] = B64chars[n >> 12 & 0x3F];
		str[j++] = B64chars[n >> 6 & 0x3F];
		str[j++] = B64chars[n & 0x3F];
	}
	if (pad)  /// set padding
	{
		int n = --pad ? int(p[last]) << 8 | p[last + 1] : p[last];
		str[j++] = B64chars[pad ? n >> 10 & 0x3F : n >> 2];
		str[j++] = B64chars[pad ? n >> 4 & 0x03F : n << 4 & 0x3F];
		str[j++] = pad ? B64chars[n << 2 & 0x3F] : '=';
	}
	return result;
}

const std::string b64decode(const void* data, const size_t& len)
{
	if (len == 0) return "";

	unsigned char* p = (unsigned char*)data;
	size_t j = 0,
		pad1 = len % 4 || p[len - 1] == '=',
		pad2 = pad1 && (len % 4 > 2 || p[len - 2] != '=');
	const size_t last = (len - pad1) / 4 << 2;
	std::string result(last / 4 * 3 + pad1 + pad2, '\0');
	unsigned char* str = (unsigned char*)&result[0];

	for (size_t i = 0; i < last; i += 4)
	{
		int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}
	if (pad1)
	{
		int n = B64index[p[last]] << 18 | B64index[p[last + 1]] << 12;
		str[j++] = n >> 16;
		if (pad2)
		{
			n |= B64index[p[last + 2]] << 6;
			str[j++] = n >> 8 & 0xFF;
		}
	}
	return result;
}

std::string b64encode(const std::string& str)
{
	return b64encode(str.c_str(), str.size());
}

std::string b64decode(const std::string& str64)
{
	return b64decode(str64.c_str(), str64.size());
}


bool SpectroFobia = true;
bool Revenger = false;
bool Diss = false;
struct cpuid_regs
{
	DWORD   Eax;
	DWORD   Ebx;
	DWORD   Ecx;
	DWORD   Edx;
};
std::string SplitIntoChars(DWORD Value)
{
	std::string Str;
	char const* pCursor = (char const*)&Value;
	for (int i = 0; i < sizeof(Value); ++i) {
		Str += pCursor[i];
	}
	return Str;
}
std::string GetCpuVendorSubstring(DWORD Eax)
{
	cpuid_regs Regs;
	__cpuid((int*)&Regs, Eax);
	std::string Str;
	Str += SplitIntoChars(Regs.Eax);
	Str += SplitIntoChars(Regs.Ebx);
	Str += SplitIntoChars(Regs.Ecx);
	Str += SplitIntoChars(Regs.Edx);
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	Str += sysinfo.dwNumberOfProcessors;
	Str += sysinfo.dwProcessorType;
	Str += sysinfo.wProcessorArchitecture;
	Str += sysinfo.wProcessorLevel;
	Str += sysinfo.wProcessorRevision;
	std::string out;
    out = b64encode(Str);
	std::string out2;
	out2 = out + b64encode(out);
	return out2;
}

std::string GetCpuVendorString()
{
	std::string VendorString;
	cpuid_regs Regs;
	__cpuid((int*)&Regs, 0x80000000);
	if (Regs.Eax >= 0x80000004)
	{
		VendorString =
			GetCpuVendorSubstring(0x80000002) +
			GetCpuVendorSubstring(0x80000003) +
			GetCpuVendorSubstring(0x80000004)
			;
	}
	return VendorString;
}
std::string GetHashText(const void * data, const size_t data_size)
{
	HCRYPTPROV hProv = NULL;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		return "";
	}

	BOOL hash_ok = FALSE;
	HCRYPTPROV hHash = NULL;

	hash_ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);

	if (!hash_ok)
	{
		CryptReleaseContext(hProv, 0);
		return "";
	}

	if (!CryptHashData(hHash, static_cast<const BYTE *>(data), static_cast<DWORD>(data_size), 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}

	DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&cbHashSize, &dwCount, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}

	std::vector<BYTE> buffer(cbHashSize);

	if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&buffer[0]), &cbHashSize, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}

	std::ostringstream oss;

	for (std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter)
	{
		oss.fill('0');
		oss.width(2);
		oss << std::hex << static_cast<const int>(*iter);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	return oss.str();
}

std::string getFirstHddSerialNumber() {
	//get a handle to the first physical drive
	HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) return {};
	std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)> hDevice{ h, [](HANDLE handle) {CloseHandle(handle); } };
	STORAGE_PROPERTY_QUERY storagePropertyQuery{};
	storagePropertyQuery.PropertyId = StorageDeviceProperty;
	storagePropertyQuery.QueryType = PropertyStandardQuery;
	STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader{};
	DWORD dwBytesReturned = 0;
	if (!DeviceIoControl(hDevice.get(), IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
		&storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER), &dwBytesReturned, NULL))
		return {};
	const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
	std::unique_ptr<BYTE[]> pOutBuffer{ new BYTE[dwOutBufferSize]{} };
	if (!DeviceIoControl(hDevice.get(), IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
		pOutBuffer.get(), dwOutBufferSize, &dwBytesReturned, NULL))
		return {};
	STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(pOutBuffer.get());
	const DWORD dwSerialNumberOffset = pDeviceDescriptor->SerialNumberOffset;
	if (dwSerialNumberOffset == 0) return {};
	const char* serialNumber = reinterpret_cast<const char*>(pOutBuffer.get() + dwSerialNumberOffset);
	std::string s = serialNumber;
	s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
	return s;
}


#define PATH "/"
#define HOST XORSTR("host")




std::string GetUrlData(std::string url)
{
	std::string request_data = "";

	HINTERNET hIntSession = InternetOpenA("", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	if (!hIntSession)
	{
		return request_data;
	}

	HINTERNET hHttpSession = InternetConnectA(hIntSession, HOST, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, NULL);

	if (!hHttpSession)
	{
		return request_data;
	}

	HINTERNET hHttpRequest = HttpOpenRequestA(hHttpSession, XORSTR("GET"), url.c_str()
		, 0, 0, 0, INTERNET_FLAG_RELOAD, 0);

	if (!hHttpSession)
	{
		return request_data;
	}

	const char* szHeaders = XORSTR("Content-Type: text/html\r\nUser-Agent: License");
	char szRequest[1024] = { 0 };

	if (!HttpSendRequestA(hHttpRequest, szHeaders, static_cast<DWORD>(strlen(szHeaders)), szRequest, static_cast<DWORD>(strlen(szRequest))))
	{
		return request_data;
	}

	CHAR szBuffer[1024] = { 0 };
	DWORD dwRead = 0;

	while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
	{
		request_data.append(szBuffer, dwRead);
	}

	InternetCloseHandle(hHttpRequest);
	InternetCloseHandle(hHttpSession);
	InternetCloseHandle(hIntSession);

	return request_data;
}

