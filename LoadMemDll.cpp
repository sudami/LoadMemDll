#include "LoadMemDll.h"

typedef   BOOL(__stdcall *ProcDllMain)(HINSTANCE, DWORD, LPVOID);
bool LoadMemDll::LoadDll(PBYTE lpBuf,DWORD dwSize, OUT LPVOID* pMemDll)
{
	LPBYTE pAllocMemDll = NULL;
	*pMemDll = NULL;				//Init outptr nullptr
	if (!CheckIsAviliableDll(lpBuf))
		return false;

	m_pDosHeader = (PIMAGE_DOS_HEADER)lpBuf;
	m_pNtHeader = (PIMAGE_NT_HEADERS)(lpBuf + m_pDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	DWORD dwSecAlign = m_pNtHeader->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = m_pNtHeader->OptionalHeader.FileAlignment;

	pAllocMemDll = (LPBYTE)VirtualAlloc(NULL, m_pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pAllocMemDll == NULL)
		return false;
	ZeroMemory(pAllocMemDll, m_pNtHeader->OptionalHeader.SizeOfImage);

	//copy header to alloc mem
	DWORD dwHeaderSize = m_pNtHeader->OptionalHeader.SizeOfHeaders;
	memmove(pAllocMemDll,lpBuf,dwHeaderSize);						

	//循环加载每一个节区
	while (pSecHeader->VirtualAddress && pSecHeader->SizeOfRawData)		
	{
		DWORD dwSecImageSize = AlignSection(pSecHeader->Misc.VirtualSize,dwSecAlign);
		DWORD dwSecFileSize = pSecHeader->SizeOfRawData;
		DWORD dwRealSize = dwSecImageSize > dwSecFileSize ? dwSecFileSize : dwSecImageSize;
		memmove(pSecHeader->VirtualAddress + pAllocMemDll,pSecHeader->PointerToRawData + lpBuf, dwRealSize);

		//next section
		pSecHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pSecHeader + sizeof(IMAGE_SECTION_HEADER));
	}

	FixReloc(pAllocMemDll);

	if (!FixImportTable(pAllocMemDll))
		return false;

	//启动DllMain
	ProcDllMain pDllMain = (ProcDllMain)(m_pNtHeader->OptionalHeader.AddressOfEntryPoint + pAllocMemDll);
	bool bStatus = pDllMain((HINSTANCE)pAllocMemDll,DLL_PROCESS_ATTACH,0);
	if (!bStatus)
	{
		pDllMain((HINSTANCE)pAllocMemDll, DLL_PROCESS_DETACH, 0);
		VirtualFree(pAllocMemDll, 0,MEM_RELEASE);
		return false;
	}

	*pMemDll = pAllocMemDll;
	return true;
}

PBYTE LoadMemDll::GetRsrcDll(int nIdRsrc,TCHAR *szTypeRsrc,OUT DWORD *dwSize)
{
	HRSRC hRsrc = FindResourceA(GetModuleHandleA(NULL), MAKEINTRESOURCE(nIdRsrc), szTypeRsrc);
	HGDIOBJ hGdi = LoadResource(GetModuleHandleA(NULL),hRsrc);
	PBYTE pBuf = (PBYTE)LockResource(hGdi);
	*dwSize = SizeofResource(GetModuleHandleA(NULL),hRsrc);
	return pBuf;
}

DWORD LoadMemDll::GetMemProcAddress(PBYTE pMemDll, TCHAR * szFuncName)
{
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pMemDll);
	PDWORD pAddressOfNamesTable =  (PDWORD)(pExportDirectory->AddressOfNames + pMemDll);
	PWORD pAddressOfOridinalTable = (PWORD)(pExportDirectory->AddressOfNameOrdinals + pMemDll);

	if (IsBadReadPtr(szFuncName, 1))			//序号
	{
		WORD Base = pExportDirectory->Base;
		WORD index = (WORD)szFuncName - Base;
		if (index >= pExportDirectory->NumberOfFunctions)
			return 0;
		return *(PWORD)((PDWORD)(pExportDirectory->AddressOfFunctions + pMemDll)+ index) + (DWORD)pMemDll;
	}
	else
	{
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			if (strcmp(szFuncName, (char *)(*(pAddressOfNamesTable + i) + pMemDll)) == 0)
			{
				WORD index = *(pAddressOfOridinalTable + i);
				return *(PWORD)((PDWORD)(pExportDirectory->AddressOfFunctions + pMemDll) + index) + (DWORD)pMemDll;
			}
		}
	}
	return 0;
}

bool LoadMemDll::CheckIsAviliableDll(PBYTE pBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)(pDosHeader->e_lfanew + pBuf);
	
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			if (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
			{
				return true;
			}
		}
	}
	return false;
}

DWORD LoadMemDll::AlignSection(DWORD dwSize, DWORD Align)
{
	return ((dwSize + Align - 1) / Align * Align);
}

DWORD LoadMemDll::AlignFile(DWORD dwSize, DWORD Align)
{
	return dwSize / Align * Align;
}

void LoadMemDll::FixReloc(PBYTE pMemBuf)
{
	DWORD dwOriImage = m_pNtHeader->OptionalHeader.ImageBase;
	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pMemBuf);
	int nSizeOfRelocDirectory = m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	int nNumOfRelocAddress;
	int nSzieOfRelocBlock;
	DWORD BaseRva;
	DWORD diff = (DWORD)pMemBuf - dwOriImage;

	while (nSizeOfRelocDirectory)
	{
		nSzieOfRelocBlock = pBaseReloc->SizeOfBlock;
		if (nSzieOfRelocBlock == 0)
			break;
		nNumOfRelocAddress = (nSzieOfRelocBlock - 8) / 2;
		BaseRva = pBaseReloc->VirtualAddress;
		WORD *pTypeOffset = (WORD *)((BYTE *)pBaseReloc + 8);
		for (int nIndex = 0; nIndex < nNumOfRelocAddress ; nIndex++)		
		{
			int type = pTypeOffset[nIndex] >> 12;
			DWORD offset = pTypeOffset[nIndex] & 0x0FFF;
			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				//什么都不用干
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(PDWORD)(pMemBuf + offset + BaseRva) += diff;
				break;
			default:
				break;
			}
		}
		nSizeOfRelocDirectory -= nSzieOfRelocBlock;
		pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + nSzieOfRelocBlock);
	}
}

bool LoadMemDll::FixImportTable(PBYTE pMemBuf)
{
	//IMAGE_ORDINAL_FLAG32
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	pIID = (PIMAGE_IMPORT_DESCRIPTOR)(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pMemBuf);

	while(true)
	{
		if (pIID->Name == NULL)
			break;
		char szDllName[0x20];
		strcpy(szDllName, (char *)(pIID->Name + pMemBuf));

		HMODULE hLibrary = LoadLibraryA(szDllName);
		if (!hLibrary)
		{
			char szInfo[0x30];
			sprintf(szInfo, "未找到DLL%s", szDllName);
			MessageBoxA(0, szInfo, 0, 0);
			return false;
		}

		PIMAGE_THUNK_DATA32 pIAT_Table = (PIMAGE_THUNK_DATA32)(pIID->FirstThunk + pMemBuf);
		PIMAGE_THUNK_DATA32 pINT_Table = (PIMAGE_THUNK_DATA32)(pIID->OriginalFirstThunk + pMemBuf);
		while (true)
		{
			PIMAGE_IMPORT_BY_NAME pImpotName = (PIMAGE_IMPORT_BY_NAME)(pINT_Table->u1.AddressOfData + pMemBuf);
			if (pINT_Table->u1.AddressOfData == NULL)
				break;
			if (pINT_Table->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)		//导出序号
			{
				pIAT_Table->u1.AddressOfData = (DWORD)GetProcAddress(hLibrary, (LPCSTR)((WORD)pINT_Table->u1.Ordinal));
			}
			else
			{
				pIAT_Table->u1.AddressOfData = (DWORD)GetProcAddress(hLibrary, pImpotName->Name);
			}

			pINT_Table++;
			pIAT_Table++;
		}

		pIID++;
	}
	return true;
}

