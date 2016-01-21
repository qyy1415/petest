#pragma once

#ifdef UNICODE
typedef  fstream tfstream;
#else
typedef wfstream twfstream;
#endif // UNICODE


class CPEUtil
{
protected:
	vector<char> m_vBuf;

public:
	class CHeader
	{
	public:
		CHeader(char* pBase)
		{
			Reset(pBase);
		}
		~CHeader()
		{

		}
		void Reset(char* pBase)
		{
			pDosHeader = (IMAGE_DOS_HEADER*)pBase;
			pNTHeader = (IMAGE_NT_HEADERS*)(pBase + pDosHeader->e_lfanew);
			pOp = &pNTHeader->OptionalHeader;
		}

	public:
		IMAGE_DOS_HEADER* pDosHeader;
		IMAGE_NT_HEADERS* pNTHeader;
		IMAGE_OPTIONAL_HEADER* pOp;
	};

public:
	CPEUtil();
	~CPEUtil();

	bool Load(LPCTSTR szFile);
	bool Save(LPCTSTR szFile);
	bool AddCode(byte* pCode, DWORD dwSize);
	DWORD Rva2Fva(DWORD dwRva);
	DWORD AlignUp(DWORD x, DWORD v);
};

