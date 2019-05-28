#include "UserFunc.h"
#include <windows.h>
#include <stdio.h>


void MyExitProcess(_In_ UINT uExitCode) {
	printf("\n[+] 程序已退出，退出代码为 %d\n", uExitCode);
	ExitProcess(uExitCode);
}