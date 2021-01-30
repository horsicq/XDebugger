// copyright (c) 2019-2021 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#include "xwinapi.h"

XWinAPI::XWinAPI(QObject *parent) : XDebugger(parent)
{

}

void XWinAPI::handle_Kernel32_GetProcAddress(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,KERNEL32_GETPROCADDRESS *pData)
{
    if(handleType==HANDLE_TYPE_ENTER)
    {
        *pData={};

        pData->_hModule=pDebugger->getFunctionParameter(pFunctionInfo,0);
        pData->_lpProcName=pDebugger->getFunctionParameter(pFunctionInfo,1);

        pData->sLibrary=pDebugger->getMapDLL()->value(pData->_hModule).sName;

    #ifndef Q_OS_WIN64
        if(pData->_lpProcName&0xFFFF0000)
        {
            pData->bIsOrdinal=false;
            pData->sFunction=pDebugger->read_ansiString(pData->_lpProcName);
        }
    #else
        if(pData->_lpProcName&0xFFFFFFFFFFFF0000)
        {
            pData->bIsOrdinal=false;
            pData->sFunction=pDebugger->read_ansiString(pData->_lpProcName);
        }
    #endif
        else
        {
            pData->bIsOrdinal=true;
            pData->nOrdinal=pData->_lpProcName;
        }
    }
    else if(handleType==HANDLE_TYPE_LEAVE)
    {
        pData->nResult=pDebugger->getFunctionResult(pFunctionInfo);
    }
}

void XWinAPI::handle_User32_MessageBox(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,bool bIsUnicode,USER32_MESSAGEBOX *pData)
{
    if(handleType==HANDLE_TYPE_ENTER)
    {
        *pData={};

        pData->_hWnd=pDebugger->getFunctionParameter(pFunctionInfo,0);
        pData->_lpText=pDebugger->getFunctionParameter(pFunctionInfo,1);
        pData->_lpCaption=pDebugger->getFunctionParameter(pFunctionInfo,2);
        pData->_uType=pDebugger->getFunctionParameter(pFunctionInfo,3);

        pData->bIsUnicode=bIsUnicode;

        if(bIsUnicode)
        {
            pData->sText=pDebugger->read_unicodeString(pData->_lpText);
            pData->sCaption=pDebugger->read_unicodeString(pData->_lpCaption);
        }
        else
        {
            pData->sText=pDebugger->read_ansiString(pData->_lpText);
            pData->sCaption=pDebugger->read_ansiString(pData->_lpCaption);
        }
    }
    else if(handleType==HANDLE_TYPE_LEAVE)
    {
        pData->nResult=pDebugger->getFunctionResult(pFunctionInfo);
    }
}

void XWinAPI::handle_Kernel32_ExitProcess(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,KERNEL32_EXITPROCESS *pData)
{
    if(handleType==HANDLE_TYPE_ENTER)
    {
        *pData={};

        pData->_uExitCode=pDebugger->getFunctionParameter(pFunctionInfo,0);
    }
    else if(handleType==HANDLE_TYPE_LEAVE)
    {
        pData->nResult=pDebugger->getFunctionResult(pFunctionInfo);
    }
}

void XWinAPI::handle_Kernel32_VirtualAlloc(XDebugger *pDebugger, XDebugger::FUNCTION_INFO *pFunctionInfo, XWinAPI::HANDLE_TYPE handleType,KERNEL32_VIRTUALALLOC *pData)
{
    if(handleType==HANDLE_TYPE_ENTER)
    {
        *pData={};

        pData->_lpAddress=pDebugger->getFunctionParameter(pFunctionInfo,0);
        pData->_dwSize=pDebugger->getFunctionParameter(pFunctionInfo,1);
        pData->_flAllocationType=pDebugger->getFunctionParameter(pFunctionInfo,2);
        pData->_flProtect=pDebugger->getFunctionParameter(pFunctionInfo,3);
    }
    else if(handleType==HANDLE_TYPE_LEAVE)
    {
        pData->nResult=pDebugger->getFunctionResult(pFunctionInfo);
    }
}
