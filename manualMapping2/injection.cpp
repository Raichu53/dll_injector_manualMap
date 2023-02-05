#include "injection.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall shellcode(MANUAL_MAPPING_DATA* pData);

bool manualMapping(HANDLE processHandle, const char* dllPath) {


	/*
	* https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	Plan :
	first, i need to read my dll in binary and store it (dllContent)
	now that my dll content is stored, i need to find a place to put it in the game
	*/
	IMAGE_DOS_HEADER* dllDosHeader		= nullptr;
	IMAGE_NT_HEADERS* dllNTHeaders		= nullptr;
	IMAGE_FILE_HEADER* dllFileHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER* dllOptHeader = nullptr;
	IMAGE_SECTION_HEADER* sectionHeader = nullptr;
	BYTE* targetLocation				= nullptr;

	
	std::ifstream File(dllPath, std::ios::ate | std::ios::binary);
	if (File.fail()) {
		std::cerr << "Error : can't open dll";
		File.close();
		return false;
	}

	UINT fileSize = File.tellg();
	char* dllContent = new char[fileSize];
	if (dllContent == nullptr) {
		std::cerr << "Error : can't allocate memory for the dll content";
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(dllContent, fileSize);
	File.close();
	dllDosHeader = (IMAGE_DOS_HEADER*)(dllContent);
	if (!dllDosHeader->e_magic == 0x5A4D) {
		std::cerr << "Error : dll PE format is not correct";
		delete dllContent;
		return false;
	}

	/*
	! Warning !
	dllDosHeader + dllDosHeader->e_lfanew is wrong because adding (0xF0 here) 
	to a IMAGE_DOS_HEADER is the same as 0x3E00 to a BYTE (
	solution : casting dllDosHeader to (BYTE*)
	*/
	dllNTHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dllDosHeader + dllDosHeader->e_lfanew);
	dllFileHeader = &dllNTHeaders->FileHeader;
	dllOptHeader = &dllNTHeaders->OptionalHeader;

	
	targetLocation = (BYTE*)VirtualAllocEx(processHandle,(LPVOID)dllOptHeader->ImageBase, dllOptHeader->SizeOfImage,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (targetLocation == nullptr) {
		targetLocation = (BYTE*)VirtualAllocEx(processHandle, nullptr, dllOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (targetLocation == nullptr) {
			std::cerr << "Error : memory allocation in target process failed";
			delete dllContent;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data = { 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAdress = (f_get_proc_address)GetProcAddress;

	//the section header is right after the optional header
	sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)dllOptHeader + dllFileHeader->SizeOfOptionalHeader);
	/*
	copying the dll content into the process
	In order to copy the 9 sections (text,rdata,data...) corrrectly into the allocated memory (targetLocation),
	we add the Virtual address of the section to the targetLocation 
	we take the data we want to write using the pointer to the rawData of the section
	finaly we set the size of raw data in the section
	we increment i and the sectionHeader ptr to goto the next sectionHeader every iteration

	This way we don't copy the PE headers and sectionHeaders into the targetLocation
	*/
	for (int i = 0; i < dllFileHeader->NumberOfSections; i++,sectionHeader++) {
		if (sectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(processHandle, targetLocation + sectionHeader->VirtualAddress,
				dllContent + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, nullptr)) {

				std::cout << "Error : mapping sections failed";
				VirtualFreeEx(processHandle, targetLocation, 0, MEM_RELEASE);
				delete dllContent;
				return false;
			}
		}
	}

	memcpy(dllContent,&data, sizeof(data));
	WriteProcessMemory(processHandle, targetLocation, dllContent, 0x1000, nullptr);
	delete dllContent; 
	void* pShellCode = VirtualAllocEx(processHandle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pShellCode == nullptr) {
		std::cout << "Error : memory allocation for shellCode failed";
		VirtualFreeEx(processHandle, targetLocation, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(processHandle, pShellCode, shellcode, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellCode,targetLocation, 0, nullptr);
	if (hThread == nullptr) {
		std::cout << "Error : CreateRemoteThread() failed";
		VirtualFreeEx(processHandle, targetLocation, 0, MEM_RELEASE);
		VirtualFreeEx(processHandle, pShellCode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);
	
	HMODULE check = nullptr;
	while (!check) {
		MANUAL_MAPPING_DATA data_checked = { 0 };
		ReadProcessMemory(processHandle, targetLocation, &data_checked, sizeof(MANUAL_MAPPING_DATA), nullptr);
		check = data_checked.hMod;
		Sleep(10);
	}
	
	VirtualFreeEx(processHandle, pShellCode, 0, MEM_RELEASE);
	return true;
}

void __stdcall shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
		return;

	//pBase is the base address of the dll but also holding data
	BYTE* pBase = (BYTE*)pData;
	IMAGE_NT_HEADERS* NTHeaders = (IMAGE_NT_HEADERS*)(pBase + ((IMAGE_DOS_HEADER*)(pBase))->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOpt = &NTHeaders->OptionalHeader;

	//when we inject our code we can't call any functions so I use pointer to the functions
	f_load_libraryA _LoadLibraryA = pData->pLoadLibraryA;
	f_get_proc_address _GetProcAddress = pData->pGetProcAdress;
	f_dll_entry_point _DllMain = (f_dll_entry_point)(pBase + pOpt->AddressOfEntryPoint);


	//now i'll check if pBase is at imageBase 
	BYTE* dif = pBase - pOpt->ImageBase;
	if (dif) { //we are not at imagebase, relocating

		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) { return; }
		IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pRelocData->VirtualAddress) {
			//instead could have used sizeof(IMAGE_BASE_RELOCATION) <=> 2*sizeof(DWORD)
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - (2 * sizeof(DWORD))) / sizeof(WORD); //IMAGE_BASE_RELOCATION struct
			WORD* pRelativeInfo = (WORD*)((BYTE*)pRelocData + 2 * sizeof(sizeof(DWORD)));
			for (unsigned int i = 0; i < AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					PUINT_PTR pPatch = (PUINT_PTR)(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
					*pPatch += (UINT_PTR)(dif);
				}
			}
			pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
		}
	}
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {

		IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDesc->Name) {

			char* szMod = (char*)(pBase + pImportDesc->Name);
			HMODULE hDll = _LoadLibraryA(szMod);
			ULONG_PTR* thunkRef = (ULONG_PTR*)(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR* funcRef = (ULONG_PTR*)(pBase + pImportDesc->FirstThunk);

			if (thunkRef == nullptr) {
				thunkRef = funcRef;
			}

			for (; *thunkRef; ++thunkRef, ++funcRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
					*funcRef = _GetProcAddress(hDll, (char*)(*thunkRef & 0xFFFF));
				}
				else {
					IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*thunkRef));
					*funcRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDesc;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

