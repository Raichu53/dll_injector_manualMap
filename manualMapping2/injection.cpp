#include "injection.h"

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

	targetLocation = (BYTE*)VirtualAllocEx(processHandle, nullptr, dllOptHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (targetLocation == nullptr) {
		std::cerr << "Error : memory allocation in target process failed";
		delete dllContent;
		return false;
	}

	//the section header is right after the optional header
	sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)dllOptHeader + dllFileHeader->SizeOfOptionalHeader);

	/*
	copying the dll content into the process
	In order to copy the 9 sections (text,rdata,data...) corrrectly into the allocated memory (targetLocation),
	we add the Virtual address of the section to the targetLocation 
	we take the data we want to write using the pointer to the rawData of the section
	finaly we set the size of raw data in the section
	we increment i and the sectionHeader ptr to goto the next section every iteration

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



	VirtualFreeEx(processHandle, targetLocation, 0, MEM_RELEASE);
	delete dllContent;
	return true;
}