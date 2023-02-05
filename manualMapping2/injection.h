#pragma once

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <fstream>

typedef HMODULE(WINAPI* f_load_libraryA)(const char* fileName);
typedef UINT_PTR(WINAPI* f_get_proc_address)(HMODULE hMod, const char* moduleName);
typedef BOOL(WINAPI* f_dll_entry_point)(void* hMod, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA {
	f_load_libraryA pLoadLibraryA;
	f_get_proc_address pGetProcAdress;
	HMODULE hMod;
};

bool manualMapping(HANDLE processHandle, const char* dllPath);