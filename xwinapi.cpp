#include "xwinapi.h"

XWinAPI::XWinAPI(QObject *parent) : XDebugger(parent)
{

}

XWinAPI::KERNEL32_GETPROCADDRESS XWinAPI::handle_Kernel32_GetProcAddress(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo)
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
        result.sFunction=pDebugger->read_ansiString(result._lpProcName);
    }

    return result;
}

XWinAPI::USER32_MESSAGEBOX XWinAPI::handle_User32_MessageBox(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo, bool bIsUnicode)
{
    USER32_MESSAGEBOX result={};

    result.nResult=pDebugger->getFunctionResult(pFunctionInfo);
    result._hWnd=pDebugger->getFunctionParameter(pFunctionInfo,0);
    result._lpText=pDebugger->getFunctionParameter(pFunctionInfo,1);
    result._lpCaption=pDebugger->getFunctionParameter(pFunctionInfo,2);
    result._uType=pDebugger->getFunctionParameter(pFunctionInfo,3);

    result.bIsUnicode=bIsUnicode;

    if(bIsUnicode)
    {
        result.sText=pDebugger->read_unicodeString(result._lpText);
        result.sCaption=pDebugger->read_unicodeString(result._lpCaption);
    }
    else
    {
        result.sText=pDebugger->read_ansiString(result._lpText);
        result.sCaption=pDebugger->read_ansiString(result._lpCaption);
    }

    return result;
}

XWinAPI::KERNEL32_EXITPROCESS XWinAPI::handle_Kernel32_ExitProcess(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo)
{
    KERNEL32_EXITPROCESS result={};

    result.nResult=pDebugger->getFunctionResult(pFunctionInfo);
    result._uExitCode=pDebugger->getFunctionParameter(pFunctionInfo,0);

    return result;
}
