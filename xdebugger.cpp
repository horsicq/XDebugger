// copyright (c) 2019 hors<horsicq@gmail.com>
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
#include "xdebugger.h"

XDebugger::XDebugger(QObject *parent) : QObject(parent)
{

}

bool XDebugger::loadFile(QString sFileName, XDebugger::OPTIONS *pOptions)
{
    bool bSuccess=false;
    clear();
    qint32 nFlags=DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS|CREATE_SUSPENDED;

    if(!pOptions->bShowWindow)
    {
        nFlags|=CREATE_NO_WINDOW;
    }

    sturtupInfo.cb=sizeof(sturtupInfo);

    if(CreateProcessW((const wchar_t*)sFileName.utf16(),0,0,0,0,nFlags,0,0,&sturtupInfo,&processInfo))
    {
        if(ResumeThread(processInfo.hThread)!=(DWORD)-1)
        {
            while(true)
            {
                DEBUG_EVENT DBGEvent={0};
                WaitForDebugEvent(&DBGEvent, INFINITE);

                if(DBGEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)
                {
                    createProcessDebugInfo=DBGEvent.u.CreateProcessInfo;

                    onCreateProcessDebugEvent(&DBGEvent);
                }
                else if(DBGEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
                {
                    onCreateThreadDebugEvent(&DBGEvent);
                }
                else if(DBGEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)
                {
                    onExitProcessDebugEvent(&DBGEvent);
                    break;
                }
                else if(DBGEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT)
                {
                    onExitThreadDebugEvent(&DBGEvent);
                }
                else if(DBGEvent.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT)
                {
                    DLL_INFO dllInfo={};
                    dllInfo.nImageBase=(qint64)DBGEvent.u.LoadDll.lpBaseOfDll;
                    dllInfo.nImageSize=XProcess::getImageSize(getProcessHandle(),dllInfo.nImageBase);
                    dllInfo.sFileName=XProcess::getFileNameByHandle(DBGEvent.u.LoadDll.hFile);
                    dllInfo.sName=QFileInfo(dllInfo.sFileName).baseName();

                    mapDLL.insert(dllInfo.nImageBase,dllInfo);

                    onLoadDllDebugEvent(&dllInfo);
                }
                else if(DBGEvent.dwDebugEventCode==UNLOAD_DLL_DEBUG_EVENT)
                {
                    qint64 nDllBase=(qint64)DBGEvent.u.UnloadDll.lpBaseOfDll;
                    DLL_INFO dllInfo=mapDLL.value(nDllBase);

                    mapDLL.remove(nDllBase);

                    onUnloadDllDebugEvent(&dllInfo);
                }
                else if(DBGEvent.dwDebugEventCode==OUTPUT_DEBUG_STRING_EVENT)
                {
                    onOutputDebugStringEvent(&DBGEvent);
                }
                else if(DBGEvent.dwDebugEventCode==RIP_EVENT)
                {
                    onRipEvent(&DBGEvent);
                }
                else if(DBGEvent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)
                {

                }

                ContinueDebugEvent(DBGEvent.dwProcessId,DBGEvent.dwThreadId,DBG_CONTINUE);
            }

            bSuccess=true;
        }
    }


    return bSuccess;
}

HANDLE XDebugger::getProcessHandle()
{
    return createProcessDebugInfo.hProcess;
}

bool XDebugger::addBP(qint64 nAddress, XDebugger::BREAKPOINT *pBP)
{
    // TODO
    return false;
}

bool XDebugger::removeBP(qint64 nAddress)
{
    bool bResult=false;

    if(mapBP.contains(nAddress))
    {
        // TODO restore bytes etc
        mapBP.remove(nAddress);
        bResult=true;
    }

    return bResult;
}

void XDebugger::clear()
{
    processInfo={};
    sturtupInfo={};
    createProcessDebugInfo={};
    mapDLL.clear();
    mapBP.clear();
}
