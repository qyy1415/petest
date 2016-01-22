#include "stdafx.h"
#include "PEUtil.h"
#include <assert.h>

CPEUtil::CPEUtil()
{
}


CPEUtil::~CPEUtil()
{
}

DWORD CPEUtil::AlignUp(DWORD x, DWORD v)
{
	if (x%v == 0)
		return x;
	return x + v - x%v;
}

bool CPEUtil::Load(LPCTSTR szFile)
{
	tfstream f(szFile, ios::in | ios::binary);
	if (!f.is_open())
		return false;
	f.seekg(0, ios::end);
	m_vBuf.assign(f.tellg(), 0);
	f.seekg(0, ios::beg);

	f.read(m_vBuf.data(), m_vBuf.size());

	f.close();

	return true;
}

bool CPEUtil::Save(LPCTSTR szFile)
{
	if (m_vBuf.empty())
		return false;

	tfstream f(szFile, ios::out | ios::binary);

	if (!f.is_open())
		return false;

	f.write(m_vBuf.data(), m_vBuf.size());
	f.close();

	return true;
}

bool CPEUtil::AddCode(byte * pCode, DWORD dwSize)
{
	CHeader h(m_vBuf.data());
	DWORD dwBase = 0;
	auto pSec = IMAGE_FIRST_SECTION(h.pNTHeader);

	// 找空隙
	for (size_t i = 0; i < h.pNTHeader->FileHeader.NumberOfSections; i++, pSec++)
	{
		if (pSec->SizeOfRawData > 0 &&
			pSec->SizeOfRawData > (pSec->Misc.VirtualSize + dwSize))
		{
			dwBase = pSec->VirtualAddress + pSec->Misc.VirtualSize;
			break;
		}
	}
	if (!dwBase)
	{
		// 空隙不够大，添加一个新的区段
		pSec = IMAGE_FIRST_SECTION(h.pNTHeader) +h.pNTHeader->FileHeader.NumberOfSections;
		memset(pSec, 0, sizeof(pSec));
		pSec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
		strcpy_s((char*)pSec->Name, sizeof(pSec->Name), ".add");

		auto pSecPrev = pSec - 1;
		pSec->SizeOfRawData = AlignUp(dwSize, h.pOp->FileAlignment);
		pSec->PointerToRawData = AlignUp(pSecPrev->PointerToRawData + pSecPrev->SizeOfRawData, h.pOp->FileAlignment);
		pSec->VirtualAddress = AlignUp(pSecPrev->VirtualAddress + max(pSecPrev->SizeOfRawData, pSecPrev->Misc.VirtualSize), h.pOp->SectionAlignment);
		dwBase = pSec->VirtualAddress;
		//
		m_vBuf.insert(m_vBuf.end(), pSec->SizeOfRawData, 0);
		h.Reset(m_vBuf.data());
		pSec = IMAGE_FIRST_SECTION(h.pNTHeader) + h.pNTHeader->FileHeader.NumberOfSections;
		h.pNTHeader->FileHeader.NumberOfSections += 1; // 增加一个区段
		h.pOp->SizeOfImage += AlignUp(pSec->SizeOfRawData, h.pOp->SectionAlignment); // 修改映象文件大小
	}

	byte* pWrite = (byte*)(m_vBuf.data() + Rva2Fva(dwBase));
	DWORD dwJmp = h.pNTHeader->OptionalHeader.AddressOfEntryPoint - dwBase - dwSize;
	memcpy(pWrite, pCode, dwSize-sizeof(DWORD)); // pCode 最后5个字节为 jmp 00000000 (0xe9,0x00,0x00,0x00,0x00),作跳转用
	memcpy(pWrite + dwSize - sizeof(DWORD), &dwJmp, sizeof(DWORD));

	pSec->Misc.VirtualSize += dwSize;
	pSec->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	h.pNTHeader->OptionalHeader.AddressOfEntryPoint = dwBase;

	return true;
}

bool CPEUtil::AddImportTable(LPCSTR szDllName, LPCSTR szFunName)
{
	DWORD dwNeedSize = 0;
	CHeader h(&m_vBuf[0]);

	dwNeedSize = h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + sizeof(IMAGE_IMPORT_DESCRIPTOR);
	dwNeedSize += strlen(szDllName) + 1;
	dwNeedSize += sizeof(IMAGE_THUNK_DATA) * 2 * 2;
	dwNeedSize += sizeof(IMAGE_IMPORT_BY_NAME) + strlen(szFunName);

	auto pSec = IMAGE_FIRST_SECTION(h.pNTHeader);
	DWORD dwBase = 0;
	for (size_t i = 0; i < h.pNTHeader->FileHeader.NumberOfSections ; i++, pSec++)
	{
		if (pSec->SizeOfRawData > 0 &&
			pSec->SizeOfRawData >= (pSec->Misc.VirtualSize + dwNeedSize))
		{
			dwBase = pSec->VirtualAddress + pSec->Misc.VirtualSize;
			break;
		}
	}
	if (!dwBase) // not enough space, so add a new section
	{
		vector<byte> tmpCode(dwNeedSize, 0);
		AddCode(tmpCode.data(), dwNeedSize);
		h.Reset(&m_vBuf[0]);
		pSec = IMAGE_FIRST_SECTION(h.pNTHeader) + h.pNTHeader->FileHeader.NumberOfSections-1;
		dwBase = pSec->VirtualAddress;
		pSec->Misc.VirtualSize = 0;
		pSec->Characteristics |= IMAGE_SCN_MEM_WRITE;
	}
	vector<char> szBuf(dwNeedSize, 0);
	DWORD dwPos = 0;
	PIMAGE_IMPORT_DESCRIPTOR pDes = (PIMAGE_IMPORT_DESCRIPTOR)(m_vBuf.data()+Rva2Fva(h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	memcpy(szBuf.data(), pDes, h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	PIMAGE_IMPORT_DESCRIPTOR pBgn = pDes;
	for (; pDes->Characteristics; pDes++)
	{
		if (0 == strcmp(m_vBuf.data() + Rva2Fva(pDes->Name), szDllName))
			return false; // already exist
	}
	dwPos += DWORD(pDes - pBgn)*sizeof(IMAGE_IMPORT_DESCRIPTOR);
	pDes = (PIMAGE_IMPORT_DESCRIPTOR)&szBuf[dwPos];
	dwPos += sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
	char* szdll = &szBuf[dwPos];
	strcpy_s(szdll, strlen(szDllName)+1, szDllName);
	pDes->Name = dwBase + DWORD(szdll - szBuf.data());
	dwPos += strlen(szdll) + 1;
	pDes->OriginalFirstThunk = dwBase + dwPos;
	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)&szBuf[dwPos];
	pDes->FirstThunk =h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size; // pDes->OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) * 2; //
	dwPos += sizeof(IMAGE_THUNK_DATA) * 4;
	pThunk->u1.AddressOfData = dwBase + dwPos;
	pThunk += 2;
	pThunk->u1.AddressOfData = dwBase + dwPos;

	PIMAGE_IMPORT_BY_NAME pImp = (PIMAGE_IMPORT_BY_NAME)&szBuf[dwPos];
	pImp->Hint = 0;
	strcpy_s(pImp->Name, strlen(szFunName)+1, szFunName);

	memcpy(m_vBuf.data()+Rva2Fva(dwBase), &szBuf[0], dwNeedSize);
	pSec->Misc.VirtualSize += dwNeedSize;
	h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size += sizeof(IMAGE_THUNK_DATA)*2;
	h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	h.pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwBase;

	return true;
}

bool CPEUtil::IsX64()
{
	CHeader h(&m_vBuf[0]);
	return h.pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386;
}

DWORD CPEUtil::Rva2Fva(DWORD dwRva)
{
	CHeader h(&m_vBuf[0]);
	auto pSec = IMAGE_FIRST_SECTION(h.pNTHeader);

	pSec += h.pNTHeader->FileHeader.NumberOfSections-1;

	assert(dwRva <= (pSec->VirtualAddress + pSec->SizeOfRawData));

	for (size_t i = 0; i < h.pNTHeader->FileHeader.NumberOfSections ; i++, pSec--)
	{
		if (dwRva >= pSec->VirtualAddress)
			return pSec->PointerToRawData + dwRva - pSec->VirtualAddress;
	}

	return 0;
}
