#define _CRT_SECURE_NO_WARNINGS
#include"resource.h"
#include"LoadMemDll.h"

typedef void (*PTestFunc)();

void main()
{
	LoadMemDll loader;
	DWORD dwSizeSrc;
	unsigned char *data = NULL;
	PBYTE pBuf = loader.GetRsrcDll(IDR_DLL_BIN3,"DLL_BIN", &dwSizeSrc);

	if (!pBuf)
	{
		OutputDebugStringA("Get Rsrc err");
		return;
	}

	PBYTE pMemDllbuf;
	if(!loader.LoadDll(pBuf, dwSizeSrc,(LPVOID *)&pMemDllbuf))
	{
		OutputDebugStringA("LoadDll err");
		return;
	}

	PTestFunc TestFunc = (PTestFunc)loader.GetMemProcAddress(pMemDllbuf,"TestFunc");
	TestFunc();


	PTestFunc TestFunc1 = (PTestFunc)loader.GetMemProcAddress(pMemDllbuf, (TCHAR*)1);
	TestFunc();

}