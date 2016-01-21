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

	if (h.pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		return false;
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
