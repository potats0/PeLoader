#include "PELoader.h"
#include "UserFunc.h"
#include <stdio.h>


static bool __stdcall IsPeFile(IN LPVOID BaseAddr) {
	//强转到image_dos_header类型
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)BaseAddr;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((UINT_PTR)BaseAddr + pDos->e_lfanew);

	if (pDos->e_magic == IMAGE_DOS_SIGNATURE && pNt->Signature == IMAGE_NT_SIGNATURE) {
		return true;
	}

	return false;
}

static PIMAGE_NT_HEADERS GetNtHeaders(IN LPVOID BaseAddr) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)BaseAddr;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((UINT_PTR)BaseAddr + pDos->e_lfanew);
	return pNt;
}


/*

*Summary: 将rva转换成VA
*Parameters:

*	Pe:  pe文件指针

*	RVA : 待转换的rva

*Return : VA

*/
static DWORD __stdcall RVA2VA(IN LPVOID pNt, IN DWORD RVA) {
	return (DWORD)pNt + RVA;
}


static LPVOID LoadPeFromFile(IN LPCWSTR PeFileName, OUT PDWORD FileSize) {

	HANDLE hFile = CreateFileW(PeFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwSize = GetFileSize(hFile, NULL);
	LPVOID lpbase = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);//哈哈，没有释放内存
	if (ReadFile(hFile, lpbase, dwSize, &dwSize, NULL)) {
		*FileSize = dwSize;
		return lpbase;
	}
	return NULL;
}


static LPVOID AllocateMemory(IN PIMAGE_NT_HEADERS pnt) {
	DWORD dwSizeOfImage = pnt->OptionalHeader.SizeOfImage;
	DWORD dwImageBaseAddr = pnt->OptionalHeader.ImageBase;
	//为了安全性，暂时将该申请的内存区域设置成可读可写，等一会再根据需要重新设置
	//必须要设置MEM_RESERVE，不然不能申请0x00400000地址
	LPVOID returnAddr = VirtualAlloc((LPVOID)dwImageBaseAddr, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (GetLastError() == 0) {
		printf("[+] 正在根据pe的加载基地址 申请内存，基地址为 0x%p\n", (LPVOID)dwImageBaseAddr);
		return returnAddr;
	}
	else if (GetLastError() && (pnt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0){
		// 如果无法申请到image推荐的基地址，并且该pe文件支持重定位的话，给他重新申请一个地址
		returnAddr = m(NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		printf("[+] pe的加载基地址不能用，正在重新申请地址中，基地址为 0x%p\n", (LPVOID)dwImageBaseAddr);
		return returnAddr;
	}
	else
	{
		//出错了，只能返回null
		return NULL;
	}
}

static void __stdcall CopyNtHeaderToMem(IN LPVOID lpPemem, IN LPVOID Header, SIZE_T size) {
	//获取nt头的size，文件对齐值，一般是一页文件对齐
	RtlCopyMemory(lpPemem, Header, size);
	printf("[+] 正在拷贝pe头到 0x%p中\n", lpPemem);
}

static void __stdcall CopySectionToMem(IN LPVOID lpPeMem, IN LPVOID lpBaseAddr, IN PIMAGE_NT_HEADERS pNt) {
	//暂时不处理内存属性，全部可读可写可执行哈哈哈哈
	DWORD dwNumOfSection = pNt->FileHeader.NumberOfSections;
	DWORD dwSectionAlignment = pNt->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSecHed = (PIMAGE_SECTION_HEADER)((UINT_PTR)pNt + sizeof(IMAGE_NT_HEADERS));

	for (DWORD index = 0; index < dwNumOfSection; index++)
	{
		DWORD dwRva = pSecHed->VirtualAddress;
		DWORD dwFOA = pSecHed->PointerToRawData;
		DWORD dwSize = pSecHed->SizeOfRawData;
		//拷贝源是文件对齐的foa
		LPVOID SecDataSrc = (LPVOID)((UINT_PTR)lpBaseAddr + (UINT_PTR)dwFOA);
		//目的地址是RV
		LPVOID SecDataDst = (LPVOID)RVA2VA(lpPeMem, dwRva);
		//开始拷贝
		RtlCopyMemory(SecDataDst, SecDataSrc, dwSize);

		printf("[+] 正在拷贝 %s section 到内存的 0x%p, 大小为 %d\n", pSecHed->Name, SecDataDst, dwSize);
		pSecHed = (PIMAGE_SECTION_HEADER)((UINT_PTR)pSecHed + sizeof(IMAGE_SECTION_HEADER));
	}
	return;
}

VOID __stdcall BuildIAT(IN PIMAGE_NT_HEADERS pNt, IN LPVOID lpPeMem) {
	FARPROC procAddr;
	DWORD dwImportTableRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (dwImportTableRVA == 0) {
		//如果rva等于0的话，则说明没有导入表，不需要处理导入表
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportTab = (PIMAGE_IMPORT_DESCRIPTOR)RVA2VA(lpPeMem, dwImportTableRVA);
	//根据桥2修复就行了，不用根据桥1
	while (pImportTab->OriginalFirstThunk && pImportTab->FirstThunk) {
		char* DllName = (char*)(RVA2VA(lpPeMem, pImportTab->Name));
		printf("[+] 正在修正导入库 %s\n", DllName);

		PDWORD FirstTunkVA = (PDWORD)RVA2VA(lpPeMem, pImportTab->FirstThunk);
		HMODULE hModle = LoadLibraryA(DllName);
		while (*FirstTunkVA != 0) {
			PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(RVA2VA(lpPeMem, *FirstTunkVA));
			//这块主要是为了处理exitprocess，拦截程序的exitprocess，我们可以从这里获取程序的返回结果
			if (strcmp(pImportName->Name, "ExitProcess") == 0) {
				procAddr = (FARPROC)& MyExitProcess;
			}
			else
			{
				procAddr = GetProcAddress(hModle, pImportName->Name);
			}
			*FirstTunkVA = (DWORD)procAddr;
			FirstTunkVA = (DWORD*)((DWORD)FirstTunkVA + sizeof(DWORD));
#ifdef _DEBUG
			printf("\t[+] 正在修正 %s 的导入地址， 修正后的函数地址为 0x%p\n", pImportName->Name, procAddr);
#endif // _DEBUG
		}
		printf("\n");
		pImportTab = (IMAGE_IMPORT_DESCRIPTOR*)((UINT_PTR)pImportTab + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return;


}

void __stdcall FixReloc(IN PIMAGE_NT_HEADERS pNt, IN LPVOID lpPeMem) {
	DWORD pRelocRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	//判断该文件是否有重定位表
	if (pRelocRVA == 0) {
		return;
	}

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)RVA2VA(lpPeMem, pRelocRVA);
	printf("[+] 发现重定位表，开始修正...\n");
	while (pReloc->VirtualAddress) {
		DWORD dwSizeOfBlock = (pReloc->SizeOfBlock - 8) >> 1;
		DWORD dwVa = pReloc->VirtualAddress;
		PWORD block = (PWORD)((UINT_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		printf("[+] 发现 %d块需要重定位的地址信息\n", dwSizeOfBlock);
		for (DWORD index = 0; index < dwSizeOfBlock; index++)
		{
			WORD relocBlock = *block;
			if (((relocBlock & 0xF000) >> 12) == IMAGE_REL_BASED_HIGHLOW) {
				DWORD wOffset = (relocBlock & 0x0FFF | 0x00000000) + dwVa;
				PDWORD pAddress = (PDWORD)(wOffset | (DWORD)lpPeMem);
				DWORD dwDelta = (DWORD)lpPeMem - pNt->OptionalHeader.ImageBase;
				*pAddress = *pAddress + dwDelta;
#ifdef _DEBUG
				printf("[+] 修正后的地址为 0x%08x\t\n", pAddress);
#endif
			}
			block = (PWORD)((UINT_PTR)block + sizeof(WORD));

		}
		pReloc = (PIMAGE_BASE_RELOCATION)block;
	}

	return;
}


void __stdcall Loader(IN PCWSTR ExecuteFile) {

	DWORD dwFileSize;
	//首先将pe加载到内存中，注意这里是使用的文件对齐，还暂时没有使用内存对齐加载
	LPVOID BaseAddr = LoadPeFromFile(ExecuteFile, &dwFileSize);

	//判断该文件是否是pe文件，可以与上面的顺序颠倒
	if (!IsPeFile(BaseAddr))
	{
		printf("待加载文件不是pe格式，错误");
		return;
	}

	//从文件中获取pe头
	PIMAGE_NT_HEADERS pNt = GetNtHeaders(BaseAddr);

	//根据nt的optionheader头，去判断需要申请多少内存空间。根据ImageBaseAddress，判断申请内存的基址
	LPVOID lpPeMem = AllocateMemory(pNt);

	//从dos头开始，将dos+nt 拷贝到内存中。
	CopyNtHeaderToMem(lpPeMem, BaseAddr, pNt->OptionalHeader.SizeOfHeaders);

	//处理每个节，然后拷贝到内存中
	CopySectionToMem(lpPeMem, BaseAddr, pNt);

	//到这里文件加载的pe基本上就用不到了，我们可以释放了
	VirtualFree(BaseAddr, dwFileSize, MEM_DECOMMIT);
	VirtualFree(BaseAddr, 0, MEM_RELEASE);

	//但是释放完了之后，pNt头就找不到了，我们将其修正到内存加载的区域中
	pNt = (PIMAGE_NT_HEADERS)GetNtHeaders(lpPeMem);

	//处理导入表
	BuildIAT(pNt, lpPeMem);

	//处理重定位表
	FixReloc(pNt, lpPeMem);

	//所有的东西都已经处理完了，我们直接跳转过去
	DWORD EntryOfImage = RVA2VA(lpPeMem, pNt->OptionalHeader.AddressOfEntryPoint);
	printf("[+] 所有的内容都处理完毕，跳转到addresss of entry,地址为 0x%p\n\n", (LPVOID)EntryOfImage);

	__asm {
		jmp EntryOfImage;
	}
	return;

}
