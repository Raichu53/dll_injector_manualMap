#pragma once

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <fstream>


bool manualMapping(HANDLE processHandle, const char* dllPath);