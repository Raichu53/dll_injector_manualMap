#include "injection.h"

int main(void) {

	const char* dllName		= "C:\\Users\\matt0\\source\\repos\\Raichu53\\dllmain\\Debug\\dllmain.dll";
	const char* processName	= "csgo.exe";
	//recherche du PID de l'exe dans lequel on injecte la dll
	DWORD PID = 0;
	HANDLE allProcessSnaphot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (allProcessSnaphot != INVALID_HANDLE_VALUE) {

		PROCESSENTRY32 processData = { 0 };
		processData.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(allProcessSnaphot, &processData)) {
			do
			{
				if (!strcmp(processName, processData.szExeFile)) {
					PID = processData.th32ProcessID;
				}
			} while (Process32Next(allProcessSnaphot, &processData));
		}

		if (PID) {
			HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
			if (processHandle != nullptr) {
				if (manualMapping(processHandle, dllName)) {
					
				}
			}
			CloseHandle(processHandle);
		}
	}
	CloseHandle(allProcessSnaphot);
	return 0;
}