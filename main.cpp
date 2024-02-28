#include <Windows.h>
#include <stdio.h>

BOOL Is32Bit = -1;

PIMAGE_SECTION_HEADER SearchSection(PIMAGE_NT_HEADERS32 nt32, PIMAGE_NT_HEADERS64 nt64, DWORD VA) {
	if (Is32Bit == -1)return NULL;

	if (Is32Bit)
	{
		PIMAGE_SECTION_HEADER result = (PIMAGE_SECTION_HEADER)((DWORD)nt32 + sizeof(IMAGE_NT_HEADERS32));

		for (int i = 0; i < nt32->FileHeader.NumberOfSections; i++) {
			if (result->VirtualAddress == VA)return result;

			result = (PIMAGE_SECTION_HEADER)((DWORD)result + sizeof(IMAGE_SECTION_HEADER));
		}

	}
	else {
		PIMAGE_SECTION_HEADER result = (PIMAGE_SECTION_HEADER)((DWORD)nt64 + sizeof(IMAGE_NT_HEADERS64));

		for (int i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
			if (result->VirtualAddress == VA)return result;

			result = (PIMAGE_SECTION_HEADER)((DWORD)result + sizeof(IMAGE_SECTION_HEADER));
		}
	}

	return NULL;
}


int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("파일을 선택하세요!\n");
		return -1;
	}

	printf("파일: %s\n", argv[1]);

	HANDLE hFile = CreateFile(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("파일을 열 수 없습니다!\n");
		return -1;
	}

	DWORD NT_HEADERSsize = 0;
	DWORD NT_HEADERSoffs;
	WORD SizeOfOptionalHeader;
	WORD NumberOfSections;

	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER) - 4, 0, FILE_BEGIN);
	ReadFile(hFile, &NT_HEADERSoffs, 4, 0, 0);

	SetFilePointer(hFile, NT_HEADERSoffs + 6, 0, FILE_BEGIN);
	ReadFile(hFile, &NumberOfSections, 2, 0, 0);

	printf("섹션 수: %d\n", NumberOfSections);

	NT_HEADERSsize += sizeof(IMAGE_SECTION_HEADER) * NumberOfSections;

	SetFilePointer(hFile, NT_HEADERSoffs + 20, 0, FILE_BEGIN);
	ReadFile(hFile, &SizeOfOptionalHeader, 2, 0, 0);

	if (SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
		NT_HEADERSsize += sizeof(IMAGE_NT_HEADERS32);
		Is32Bit = TRUE;
	}
	else {
		NT_HEADERSsize += sizeof(IMAGE_NT_HEADERS64);
		Is32Bit = FALSE;
	}

	printf("32bit PE: %d\n", Is32Bit);

	PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)VirtualAlloc(NULL, NT_HEADERSsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)VirtualAlloc(NULL, NT_HEADERSsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	SetFilePointer(hFile, NT_HEADERSoffs, 0, FILE_BEGIN);
	ReadFile(hFile, nt32, NT_HEADERSsize, 0, 0);

	SetFilePointer(hFile, NT_HEADERSoffs, 0, FILE_BEGIN);
	ReadFile(hFile, nt64, NT_HEADERSsize, 0, 0);

	PIMAGE_SECTION_HEADER code_section = SearchSection(nt32, nt64, nt32->OptionalHeader.BaseOfCode);
	if (code_section == NULL) {
		printf("코드 섹션이 존재하지 않습니다.\n");
		return 0;
	}
	else {

		void* buffer = VirtualAlloc(NULL, code_section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		SetFilePointer(hFile, code_section->PointerToRawData, 0, FILE_BEGIN);
		ReadFile(hFile, buffer, code_section->SizeOfRawData, 0, 0);

		char fix_name[256];
		_snprintf_s(fix_name, sizeof(fix_name), "%s.cosc", argv[1]);

		HANDLE hResultFile = CreateFile(fix_name, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hResultFile == INVALID_HANDLE_VALUE) {
			printf("결과 파일을 만들 수 없습니다.\n");
			return 0;
		}

		WriteFile(hResultFile, buffer, code_section->SizeOfRawData, 0, 0);
		CloseHandle(hResultFile);

	}

	CloseHandle(hFile);
	return 0;
}

