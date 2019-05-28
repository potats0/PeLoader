/*
	该文件主要是存放用户自定义函数，用来hook加载pe程序的导入表程序
*/

#ifndef UserFunc
#define UserFunc
#include <windows.h>
void MyExitProcess(_In_ UINT uExitCode);
#endif // UserFunc
