// Load.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "Load.h"


LOAD_API void DoAction(void)
{
	OutputDebugString(TEXT("DoAction()"));
}
