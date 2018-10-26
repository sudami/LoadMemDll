#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<stdio.h>
#define POINTER_TYPE DWORD
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))

class LoadMemDll
{
public:
	bool LoadDll(PBYTE lpBuf, DWORD dwSize, OUT LPVOID* pMemDll);
	PBYTE GetRsrcDll(int nIdRsrc, TCHAR *szTypeRsrc, OUT DWORD *dwSize);
	DWORD GetMemProcAddress(PBYTE pMemDll, TCHAR *szFuncName);

private:
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS m_pNtHeader;

private:
	bool CheckIsAviliableDll(PBYTE pBuf);
	DWORD AlignSection(DWORD dwSize, DWORD Align);
	DWORD AlignFile(DWORD dwSize, DWORD Align);
	void FixReloc(PBYTE pMemBuf);
	bool FixImportTable(PBYTE pMemBuf);
};
