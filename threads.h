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

 
extern std::atomic<bool> should_stop;

extern bool check_access;  //Условие работы главного цикла


void check_license();

void hide();
void is();
void is_dbg3();
bool IsHTTPDebuggerInstalled();
BOOL IsVMRunning();

bool HideThread();
