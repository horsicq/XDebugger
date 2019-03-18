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

    PROCESS_INFORMATION processInfo={};
    STARTUPINFOW sturtupInfo={};

    sturtupInfo.cb=sizeof(sturtupInfo);

    if(CreateProcessW((const wchar_t*)sFileName.utf16(),0,0,0,0,nFlags,0,0,&sturtupInfo,&processInfo))
    {
        nProcessId=processInfo.dwProcessId;

        if(ResumeThread(processInfo.hThread)!=(DWORD)-1)
        {
            while(true)
            {
                DEBUG_EVENT DBGEvent={0};
                WaitForDebugEvent(&DBGEvent, INFINITE);

                quint32 nStatus=DBG_CONTINUE;

                if(DBGEvent.dwProcessId==nProcessId)
                {
                    if(DBGEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)
                    {
                        createProcessInfo.hProcess=DBGEvent.u.CreateProcessInfo.hProcess;
                        createProcessInfo.hThread=DBGEvent.u.CreateProcessInfo.hThread;
                        createProcessInfo.nBaseOfImage=(qint64)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                        createProcessInfo.nStartAddress=(qint64)DBGEvent.u.CreateProcessInfo.lpStartAddress;
                        createProcessInfo.sFileName=XProcess::getFileNameByHandle(DBGEvent.u.CreateProcessInfo.hFile);
                        createProcessInfo.nThreadLocalBase=(qint64)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;

                        addBP(createProcessInfo.nStartAddress,BP_TYPE_CC,BP_INFO_ENTRYPOINT,1);

                        onCreateProcessDebugEvent(&createProcessInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
                    {
                        CREATETHREAD_INFO createThreadInfo={};

                        createThreadInfo.hThread=DBGEvent.u.CreateThread.hThread;
                        createThreadInfo.nStartAddress=(qint64)DBGEvent.u.CreateThread.lpStartAddress;
                        createThreadInfo.nThreadLocalBase=(qint64)DBGEvent.u.CreateThread.lpThreadLocalBase;

                        onCreateThreadDebugEvent(&createThreadInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)
                    {
                        EXITPROCESS_INFO exitProcessInfo={};

                        exitProcessInfo.nExitCode=(qint32)DBGEvent.u.ExitProcess.dwExitCode;

                        onExitProcessDebugEvent(&exitProcessInfo);

                        break;
                    }
                    else if(DBGEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT)
                    {
                        EXITTHREAD_INFO exitThreadInfo={};

                        exitThreadInfo.nEcitCode=(qint32)DBGEvent.u.ExitThread.dwExitCode;

                        onExitThreadDebugEvent(&exitThreadInfo);
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
                        nStatus=DBG_EXCEPTION_NOT_HANDLED;
                    }
                }

                ContinueDebugEvent(DBGEvent.dwProcessId,DBGEvent.dwThreadId,nStatus);
            }

            bSuccess=true;
        }
    }


    return bSuccess;
}

HANDLE XDebugger::getProcessHandle()
{
    return createProcessInfo.hProcess;
}

bool XDebugger::addBP(qint64 nAddress, XDebugger::BP_TYPE bpType, XDebugger::BP_INFO bpInfo, qint32 nCount)
{
    bool bResult=false;

    BREAKPOINT bp={};
    bp.nCount=nCount;
    bp.bpInfo=bpInfo;
    bp.bpType=bpType;

    if(bpType==BP_TYPE_CC)
    {
        if(XProcess::readData(getProcessHandle(),nAddress,bp.origData,1))
        {
            if(XProcess::writeData(getProcessHandle(),nAddress,"\xCC",1))
            {
                mapBP.insert(nAddress,bp);

                bResult=true;
            }
        }
    }

    return bResult;
}

bool XDebugger::removeBP(qint64 nAddress)
{
    bool bResult=false;

    if(mapBP.contains(nAddress))
    {
        BREAKPOINT bp=mapBP.value(nAddress);
        if(bp.bpInfo==BP_TYPE_CC)
        {
            XProcess::writeData(getProcessHandle(),nAddress,bp.origData,bp.nOrigDataSize);
        }

        mapBP.remove(nAddress);
        bResult=true;
    }

    return bResult;
}

void XDebugger::clear()
{
    nProcessId=0;
    createProcessInfo={};
    mapDLL.clear();
    mapBP.clear();
}
