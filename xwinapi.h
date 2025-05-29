// copyright (c) 2019-2025 hors<horsicq@gmail.com>
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
#ifndef XWINAPI_H
#define XWINAPI_H

#include <QObject>
#include "xdebugger.h"

class XWinAPI : public XDebugger
{
    Q_OBJECT

public:
    explicit XWinAPI(QObject *parent=nullptr);

    struct KERNEL32_GETPROCADDRESS
    {
        quint64 nResult;
        quint64 _hModule;
        quint64 _lpProcName;
        QString sLibrary;
        bool bIsOrdinal;
        quint64 nOrdinal;
        QString sFunction;
    };

    struct KERNEL32_EXITPROCESS
    {
        quint64 nResult;
        quint64 _uExitCode;
    };

    struct USER32_MESSAGEBOX
    {
        quint64 nResult;
        quint64 _hWnd;
        quint64 _lpText;
        quint64 _lpCaption;
        quint64 _uType;
        QString sText;
        QString sCaption;
        bool bIsUnicode;
    };

    struct KERNEL32_VIRTUALALLOC
    {
        quint64 nResult;
        quint64 _lpAddress;
        quint64 _dwSize;
        quint64 _flAllocationType;
        quint64 _flProtect;
    };

    enum PARAMS
    {
        PARAMS_KERNEL32_GETPROCADDRESS=2,
        PARAMS_USER32_MESSAGEBOX=4,
        PARAMS_KERNEL32_EXITPROCESS=1,
    };

    enum HANDLE_TYPE
    {
        HANDLE_TYPE_ENTER=0,
        HANDLE_TYPE_LEAVE
    };

    static void handle_Kernel32_GetProcAddress(XDebugger *pDebugger,XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,KERNEL32_GETPROCADDRESS *pData);
    static void handle_User32_MessageBox(XDebugger *pDebugger,XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,bool bIsUnicode,USER32_MESSAGEBOX *pData);
    static void handle_Kernel32_ExitProcess(XDebugger *pDebugger,XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,KERNEL32_EXITPROCESS *pData);
    static void handle_Kernel32_VirtualAlloc(XDebugger *pDebugger,XDebugger::FUNCTION_INFO *pFunctionInfo,HANDLE_TYPE handleType,KERNEL32_VIRTUALALLOC *pData);
};

#endif // XWINAPI_H
