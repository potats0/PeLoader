
## PE文件加载器
模仿操作系统，加载pe文件到内存中
该项目主要是为了检测pe的学习程度，是否都完全理解了。当然没有完全理解

实现功能的如下：
1. 模仿操作系统，加载pe文件到内存中，然后执行待执行的pe文件
2. 修复IAT，reloc等重要信息

当然，这只是一个雏形，有很多工作都没有完成，TODO列表
1. DLL文件加载，这个其实很简单，只需要解析导出表，然后修正就行了
2. 绑定IAT的加载，这块懒得做
3. 延迟加载，也是懒得做

所以我们的这个小型加载器，只是负责重定位表的解析和重定位表的解析。不过对于一个小型程序来讲够用了。下面说一下思路

1. 根据pe头中的optionalheader中的SizeOfImage，申请内存。内存的基地址为ImageBase。SizeOfImage为pe文件在内存对齐的情况下，所需要的空间的大小。基地址这块的话，建议为ImageBase的地址，当然，如果该pe文件有重定位信息的话，就说明该pe文件可以加载到内存的任意位置。随后根据重定位表修正就行了
2.  根据pe头中的SizeOfHeader，获取pe头的大小。该值为文件对齐的值。根据该值，我们调用Rtlmemcopy将pe头拷贝到内存中
3.  解析pe头，获取numberofSection，根据此值，处理section。将section拷贝到内存中
4.  处理iat 分别解析iat中的内容，并修正
5.  处理重定位表。如果加载的基地址为ImageBase的话，则无需处理。否则必须处理
6.  跳转到Address of entry，开始执行pe文件

注意事项：
1. 暂时忽略loadflag等等
2. 为了方便，申请的内存可读可写可执行，并没有根据section的属性去设置
3. 被加载的程序，与主程序使用同一个heap和stack。所以不需要关注sizeofstack等值
4. 一定要修改主程序的加载基地址，修改非0x0040000的位置。不然无法申请0x00400000的地址。修改该值的话，在vs的链接选项中

下面数一下详细的操作
##### 判断是否pe文件
这块很简单，没什么说的，看代码即可
```
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)BaseAddr;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((UINT_PTR)BaseAddr + pDos->e_lfanew);

	if (pDos->e_magic == IMAGE_DOS_SIGNATURE && pNt->Signature == IMAGE_NT_SIGNATURE) {
		return true;
	}
```

##### 申请内存
根据sizeofimage去申请内存即可。当然我这个函数很粗，在imagebase无法使用的情况下，并没有判断程序是否可以重定位的情况下，强行修改imagebase。大家在使用的时候最好判断一下。
```
	DWORD dwSizeOfImage = pnt->OptionalHeader.SizeOfImage;
	DWORD dwImageBaseAddr = pnt->OptionalHeader.ImageBase;
	//为了安全性，暂时将该申请的内存区域设置成可读可写，等一会再根据需要重新设置
	//必须要设置MEM_RESERVE，不然不能申请0x00400000地址
	LPVOID returnAddr = VirtualAlloc((LPVOID)dwImageBaseAddr, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (GetLastError() == 0) {
		printf("[+] 正在根据pe的加载基地址 申请内存，基地址为 0x%p\n", (LPVOID)dwImageBaseAddr);
		return returnAddr;
	}
	else {
		returnAddr = VirtualAlloc(NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		printf("[+] pe的加载基地址不能用，正在重新申请地址中，基地址为 0x%p\n", (LPVOID)dwImageBaseAddr);
		return returnAddr;
	}
```

##### 拷贝pe头到内存中
其实对于咱们的加载器来讲。拷贝不拷贝pe头，并不会正常影响文件的执行。所以这个是一个可选的步骤。当然，我为了方便，因为在后面我会释放掉读取文件的内存。所以必须拷贝pe头。该函数比较简单，直接调用rtlcopy函数即可
```
static void __stdcall CopyNtHeaderToMem(IN LPVOID lpPemem, IN LPVOID Header, SIZE_T size) {
	//获取nt头的size，文件对齐值，一般是一页文件对齐
	RtlCopyMemory(lpPemem, Header, size);
	printf("[+] 正在拷贝pe头到 0x%p中\n", lpPemem);
}
```

##### 拷贝section到内存
这块比较简单。读取sectionHeader，header中说明的section的VA和FOA以及size，我们只需要根据这些信息，拷贝到内存的指定位置即可
```
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
```

##### 处理IAT
在PE文件中，IAT（Import address Table）和INT（Import Name Tbable）其实差不了太多。导入表的话一般都在.rdata节中。在pe中，IAT最终会存放相应函数的内存地址。下面以一个例子来说明
某程序会调用KERNEL32.dll!IsProcessorFeaturePresent函数，反汇编代码如下
```
 004013E3  6A17                      		push	00000017h
 004013E5  E84F090000                		call	jmp_KERNEL32.dll!IsProcessorFeaturePresent
 004013EA  85C0                      		test	eax,eax

```
0x004013E5中存放的为机器码，E8代表call执行，后面的值为距离该地址的偏移，偏移值为0x0000094F。
则程序会调转到 0x004013EA + 0x0000094F，也就是0x0040$D19。下面看一下该地址的反汇编代码
```
 00401D39  FF251C204000              		jmp	[KERNEL32.dll!IsProcessorFeaturePresent]
```

FF代表绝对跳转， JMP r/m32 绝对跳转（32位），下一指令地址在r/m32中给出 。也就是取出地址0x0040201c25中的值。跳转过去。而0x0040201c25，就是rdata节。该处为IAT。


而pe文件中，IAT首先会存放va，指向一个`IMAGE_IMPORT_BY_NAME`，里面存放导入函数的名称和hint。

所以修复IAT很简单，首先遍历INT，INT的结构如下
![image](https://raw.githubusercontent.com/potats0/PeLoader/master/Docs/20170820114145821.png)

遍历到INT，拿到加载dll的名字。调用loadlobrary加载。

然后通过FirstTrunk的方式，去遍历IAT。再根据IAT中的信息，调用GetProcAddress函数，获取到真正的函数地址。修正IAT即可

代码如下

```
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
```

当然，我们也可以在这里hook函数。比如我为了拦截被加载程序的结果。在修复ExitProcess函数的时候，将该函数的调用地址并没有修正到kernel32.dll中。而是修正到自己的代码中。

而hook的函数写法，按照你想hook函数的参数写就行。例
```
void MyExitProcess(_In_ UINT uExitCode) {
	printf("\n[+] 程序已退出，退出代码为 %d\n", uExitCode);
	ExitProcess(uExitCode);
}
```

##### 处理重定位表

根据重定位表的定义，里面存放着相对于ImageBase的偏移。我们需要读取到该偏移后，转换成virtual address。与当前加载的基地址进行对比。根据偏移去修复即可。重定位表的解释如图
![image](https://raw.githubusercontent.com/potats0/PeLoader/master/Docs/20170818164751341.png)

代码如下
```

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)RVA2VA(lpPeMem, pRelocRVA);
	printf("[+] 发现重定位表，开始修正...\n");
	while (pReloc->VirtualAddress) {
		DWORD dwSizeOfBlock = (pReloc->SizeOfBlock - 8) >> 1;
		DWORD dwVa = pReloc->VirtualAddress;
		PWORD block = (PWORD)((UINT_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		printf("[+] 发现 %d块需要重定位的地址信息\n", dwSizeOfBlock);
    DWORD dwDelta = (DWORD)lpPeMem - pNt->OptionalHeader.ImageBase;
		for (DWORD index = 0; index < dwSizeOfBlock; index++)
		{
			WORD relocBlock = *block;
			if (((relocBlock & 0xF000) >> 12) == IMAGE_REL_BASED_HIGHLOW) {
				DWORD wOffset = (relocBlock & 0x0FFF | 0x00000000) + dwVa;
				PDWORD pAddress = (PDWORD)(wOffset | (DWORD)lpPeMem);
				*pAddress = *pAddress + dwDelta;
#ifdef _DEBUG
				printf("[+] 修正后的地址为 0x%08x\t\n", pAddress);
#endif
			}
			block = (PWORD)((UINT_PTR)block + sizeof(WORD));
		}
		pReloc = (PIMAGE_BASE_RELOCATION)block;
	}

```


至此，一个pe文件所需要的东西，就已经全部解析完。下面我们需要跳转到入口点。入口点为optionalheader的entry of address。该值为RVA。需要转换成VA才可以。转换完成后，我们在vs中使用内联汇编。jmp跳转过去即可。代码如下

```
	DWORD EntryOfImage = RVA2VA(lpPeMem, pNt->OptionalHeader.AddressOfEntryPoint);
	printf("[+] 所有的内容都处理完毕，跳转到addresss of entry,地址为 0x%p\n\n", (LPVOID)EntryOfImage);

	__asm {
		jmp EntryOfImage;
	}
```

 
 
 ### 测试结果
 
 下面来测试一个vs 2019编译的程序，该程序使用MessageBox弹框，调用printf输出1111。该程序使用release模式编译，存在重定位表。加载截图如下
 
 ![image](https://raw.githubusercontent.com/potats0/PeLoader/master/Docs/1.png)
 
 ![image](https://raw.githubusercontent.com/potats0/PeLoader/master/Docs/20170820114145821.png)
 
 
 目前已知的bug
 1. 大部分的容错机制都没有，毕竟只是一个简单的程序。
 2. 容易出现无法申请内存的问题


vt 查询结果
![image](https://raw.githubusercontent.com/potats0/PeLoader/master/Docs/%E6%89%B9%E6%B3%A8%202019-05-29%20160303.png)

 完整的代码，请去github上看

[https://github.com/potats0/PeLoader](https://github.com/potats0/PeLoader)
