#include "injection.h"

bool manualMapping(HANDLE processHandle, const char* dllPath) {

	/*
	Plan :
	first, i need to read my dll in binary in store it (dllContent)
	now that my dll content is stored, i need to find a place to put it in the game
	*/
	IMAGE_DOS_HEADER* dllDosHeader		= nullptr;
	IMAGE_NT_HEADERS* dllNTHeaders		= nullptr;
	IMAGE_FILE_HEADER* dllFileHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER* dllOptHeader = nullptr;
	void* targetLocation				= nullptr;

	
	std::ifstream File(dllPath, std::ios::ate | std::ios::binary);
	if (File.fail()) {
		std::cerr << "Error : " << strerror(errno);
		File.close();
		return false;
	}

	UINT fileSize = File.tellg();
	char* dllContent = new char[fileSize];
	if (dllContent == nullptr) {
		std::cerr << "Error : " << strerror(errno);
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(dllContent, fileSize);
	File.close();
	dllDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dllContent);
	if (!dllDosHeader->e_magic == 0x5A4D) {
		std::cerr << "Error : " << strerror(errno);
		delete dllContent;
		return false;
	}

	/*
	! Warning !
	dllDosHeader + dllDosHeader->e_lfanew is wrong because adding (0xF0 here) 
	to a IMAGE_DOS_HEADER is the same as 0x3E00 to a BYTE (
	*/
	dllNTHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(dllContent + dllDosHeader->e_lfanew); 
	dllFileHeader = &dllNTHeaders->FileHeader;
	dllOptHeader = &dllNTHeaders->OptionalHeader;

	targetLocation = VirtualAllocEx(processHandle, nullptr, dllOptHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (targetLocation == nullptr) {
		std::cerr << "Error : " << strerror(errno);
		delete dllContent;
		return false;
	}

	

	VirtualFreeEx(processHandle, targetLocation, 0, MEM_RELEASE);
	delete dllContent;
	return true;
}