#pragma once
#include <Windows.h>
#include <iostream>
#include <winuser.h>
#include <thread>
#include <atomic>
#include <string>
#include <string.h>
#include <WinGDI.h>
#include<sstream>
#include <time.h>

#pragma comment(lib, "winmm.lib")

void macro_sleep_ms(register int real_sleep_ms);

void zero_accumulate_time();
void start_calculate_code_delay();

class WaitableTimer
{
public:

	WaitableTimer()
	{
		m_timer = ::CreateWaitableTimer(NULL, FALSE, NULL);
		if (!m_timer)
			throw std::runtime_error("Failed to create waitable time (CreateWaitableTimer), error:" + std::to_string(::GetLastError()));
	}

	~WaitableTimer()
	{
		::CloseHandle(m_timer);
		m_timer = NULL;
	}

	void Wait_mks(unsigned relativeTime100Ns)
	{
		LARGE_INTEGER dueTime = { 0 };
		dueTime.QuadPart = static_cast<LONGLONG>(relativeTime100Ns) * -10;

		BOOL res = ::SetWaitableTimer(m_timer, &dueTime, 0, NULL, NULL, FALSE);
		if (!res)
			throw std::runtime_error("SetAndWait: failed set waitable time (SetWaitableTimer), error:" + std::to_string(::GetLastError()));

		DWORD waitRes = ::WaitForSingleObject(m_timer, INFINITE);
		if (waitRes == WAIT_FAILED)
			throw std::runtime_error("SetAndWait: failed wait for waitable time (WaitForSingleObject)" + std::to_string(::GetLastError()));
	}

private:
	HANDLE m_timer;
};

extern WaitableTimer _WaitableTimer;