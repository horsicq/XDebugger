#include "xwinapi.h"

XWinAPI::XWinAPI(QObject *parent) : XDebugger(parent)
{

}

XWinAPI::KERNEL32_GETPROCADDRESS XWinAPI::handle_Kernel32_getProcAddress(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo)
{
    KERNEL32_GETPROCADDRESS result={};

    result.nResult=pDebugger->getFunctionResult(pFunctionInfo);
    result._hModule=pDebugger->getFunctionParameter(pFunctionInfo,0);
    result._lpProcName=pDebugger->getFunctionParameter(pFunctionInfo,1);

    result.sLibrary=pDebugger->getMapDLL()->value(result._hModule).sName;

    if(result._lpProcName&0x80000000) // TODO 64
    {
        result.nOrdinal=result._lpProcName&0x7FFFFFFF;
    }
    else
    {
        result.sFunction=pDebugger->readAnsiString(result._lpProcName);
    }

    return result;
}
