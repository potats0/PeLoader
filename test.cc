
#include <stdio.h>
#include <windows.h>

typedef HMODULE(__stdcall* MLoadLibrary)(LPCWSTR);
typedef int(*MyMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
typedef FARPROC(__stdcall* MyGetProcAddress)(HMODULE, LPCSTR);


PCWSTR str = TEXT("哈哈哈哈");
PCWSTR library = TEXT("User32.dll");
PCSTR procname = "MessageBoxW";


LPVOID GetKernelAddr() {
	__asm {
		mov ebx, FS: [0x30] //获取PEB
		mov ebx, [ebx + 0x0c] //获取ldr
		mov ebx, [ebx + 0x14]
		mov ebx, [ebx]
		mov ebx, [ebx]
		mov eax, [ebx + 0x10]
	}
}

DWORD __stdcall GetImporTabletFOA(
	__in IMAGE_NT_HEADERS * Pe
) {
	DWORD dwImportTableRVA = Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	return (DWORD)dwImportTableRVA;
}

DWORD __stdcall RVAToVA(LPVOID BaseAddr, DWORD RVA) {
	return (DWORD)BaseAddr + RVA;

}

LPVOID __stdcall MyLoadLibrary(const char* ProcName) {
	IMAGE_DOS_HEADER* KerAddr = (IMAGE_DOS_HEADER*)GetKernelAddr();
	IMAGE_NT_HEADERS* pKerPe = (IMAGE_NT_HEADERS*)((DWORD)KerAddr + (DWORD)(KerAddr->e_lfanew));
	DWORD dwImportVa = GetImporTabletFOA(pKerPe);
	DWORD upExportVa = RVAToVA((LPVOID)KerAddr, dwImportVa);

	IMAGE_EXPORT_DIRECTORY * ExportTable = (IMAGE_EXPORT_DIRECTORY*)upExportVa;
	LPVOID CurrentAddresOfnameArrVa = (LPVOID)RVAToVA((LPVOID)KerAddr, ExportTable->AddressOfNames);
	LPVOID currentAddressOrd = (LPVOID)RVAToVA((LPVOID)KerAddr, ExportTable->AddressOfNameOrdinals);
	DWORD AddressFuncIndex = 0;

	while ((DWORD*)CurrentAddresOfnameArrVa != 0) {
		DWORD* RVA = (DWORD*)CurrentAddresOfnameArrVa;
		DWORD NameVa = RVAToVA((LPVOID)KerAddr, *RVA);
		char* pFunctionName = (char*)NameVa;

		if (strcmp(pFunctionName, ProcName) == 0) {
			AddressFuncIndex = *(WORD*)currentAddressOrd;
			break;
		}
		CurrentAddresOfnameArrVa = (LPVOID)((DWORD)CurrentAddresOfnameArrVa + sizeof(DWORD));
		currentAddressOrd = (LPVOID)((DWORD)currentAddressOrd + sizeof(WORD));
	}


	LPVOID currentAddressOfFunctionVA = (LPVOID)RVAToVA((LPVOID)KerAddr, ExportTable->AddressOfFunctions);
	for (DWORD index = 0; (DWORD*)currentAddressOfFunctionVA != NULL; index++)
	{
		if (index == AddressFuncIndex) {
			return (LPVOID)RVAToVA((LPVOID)KerAddr, *(DWORD*)currentAddressOfFunctionVA);
		}
		currentAddressOfFunctionVA = (LPVOID)((DWORD)currentAddressOfFunctionVA + sizeof(DWORD));
	}
	return NULL;
}
int main()
{
	LPVOID Loadlib = MyLoadLibrary("LoadLibraryW");
	MLoadLibrary  GetModuleHandle1 = (MLoadLibrary)Loadlib;
	HMODULE hUser = GetModuleHandle1(L"User32.dll");

	Loadlib = MyLoadLibrary("GetProcAddress");

	MyGetProcAddress MGetProcAddress = (MyGetProcAddress)Loadlib;
	MyMessageBox MMessageBox = (MyMessageBox)(MGetProcAddress(hUser, "MessageBoxW"));
	MessageBox(NULL, str, str, MB_OK);
	printf("1111");

	ExitProcess(1);
	return 0;
}