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
    bool bResult=false;

    // TODO Check 32/64
    if(!XPE::isDll(sFileName))
    {
        bResult=_loadFile(sFileName,LOAD_TYPE_EXE,pOptions);
    }
    else
    {
        bResult=_loadFile(sFileName,LOAD_TYPE_DLL,pOptions);
    }

    return bResult;
}

HANDLE XDebugger::getProcessHandle()
{
    return createProcessInfo.hProcess;
}

QMap<qint64, XDebugger::DLL_INFO> *XDebugger::getMapDLL()
{
    return &mapDLL;
}

bool XDebugger::setBP(qint64 nAddress, XDebugger::BP_TYPE bpType, XDebugger::BP_INFO bpInfo, qint32 nCount, QVariant vInfo)
{
    bool bResult=false;

    BREAKPOINT bp= {};
    bp.nAddress=nAddress;
    bp.nCount=nCount;
    bp.bpInfo=bpInfo;
    bp.bpType=bpType;
    bp.vInfo=vInfo;

    if(bpType==BP_TYPE_CC)
    {
        bp.nOrigDataSize=1;

        if(readData(nAddress,bp.origData,bp.nOrigDataSize))
        {
            if(writeData(nAddress,(char *)"\xCC",bp.nOrigDataSize)) // TODO Check
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

        if(bp.bpType==BP_TYPE_CC)
        {
            if(writeData(nAddress,bp.origData,bp.nOrigDataSize))
            {
                mapBP.remove(nAddress);

                bResult=true;
            }
        }
    }

    return bResult;
}

bool XDebugger::addAPIHook(QString sFunctionName)
{
    if(sFunctionName!="")
    {
        QMapIterator<qint64,DLL_INFO> i(mapDLL);

        while(i.hasNext())
        {
            i.next();

            DLL_INFO dllInfo=i.value();

            _addAPIHook(dllInfo,sFunctionName);
        }

        if(!stAPIHooks.contains(sFunctionName))
        {
            stAPIHooks.insert(sFunctionName);
        }
    }

    return true;
}

bool XDebugger::removeAPIHook(QString sFunctionName)
{
    if(sFunctionName!="")
    {
        QMutableMapIterator<qint64,BREAKPOINT> i(mapBP);

        QList<qint64> listBP;

        while(i.hasNext())
        {
            i.next();

            qint64 nAddress=i.key();
            BREAKPOINT bp=i.value();

            if(bp.vInfo.toString()==sFunctionName)
            {
                listBP.append(nAddress);
            }
        }

        for(int i=0;i<listBP.count();i++)
        {
            removeBP(listBP.at(i));
        }

        if(stAPIHooks.contains(sFunctionName))
        {
            stAPIHooks.remove(sFunctionName);
        }
    }

    return true;
}

bool XDebugger::_addAPIHook(XDebugger::DLL_INFO dllInfo, QString sFunctionName)
{
    QString sLibrary=sFunctionName.section("#",0,0);
    QString sFunction=sFunctionName.section("#",1,1);

    if(dllInfo.sName.toUpper()==sLibrary.toUpper())
    {
        XProcessDevice xpd(this);

        if(xpd.openHandle(getProcessHandle(),dllInfo.nImageBase,dllInfo.nImageSize,QIODevice::ReadOnly))
        {
            XPE pe(&xpd,true,dllInfo.nImageBase); // TODO Check

            if(pe.isValid())
            {
                XPE::EXPORT_HEADER exportHeader=pe.getExport();

                int nCount=exportHeader.listPositions.count();

                for(int i=0; i<nCount; i++)
                {
                    if(exportHeader.listPositions.at(i).sFunctionName==sFunction)
                    {
                        setBP(exportHeader.listPositions.at(i).nAddress,BP_TYPE_CC,BP_INFO_API_ENTER,-1,sFunctionName);

                        break;
                    }
                }
            }

            xpd.close();
        }
    }

    return true;
}

quint64 XDebugger::getFunctionResult(XDebugger::FUNCTION_INFO *pFunctionInfo)
{
    return getRegister(pFunctionInfo->hThread,REG_NAME_EAX);
}

quint64 XDebugger::getFunctionParameter(XDebugger::FUNCTION_INFO *pFunctionInfo, qint32 nNumber)
{
    quint64 nResult=0;

#ifndef Q_OS_WIN64
    qint64 _nStackAddress=pFunctionInfo->nStackFrame+4+4*nNumber;
    nResult=read_uint32(_nStackAddress);
#else
    // TODO x64
    qCritical("getFunctionParameter");
#endif

    return nResult;
}

bool XDebugger::readData(qint64 nAddress, char *pBuffer, qint32 nBufferSize)
{
    return XProcess::readData(getProcessHandle(),nAddress,pBuffer,nBufferSize);
}

bool XDebugger::writeData(qint64 nAddress, char *pBuffer, qint32 nBufferSize)
{
    return XProcess::writeData(getProcessHandle(),nAddress,pBuffer,nBufferSize);
}

QByteArray XDebugger::read_array(qint64 nAddress, qint32 nSize)
{
    return XProcess::read_array(getProcessHandle(),nAddress,nSize);
}

QString XDebugger::read_ansiString(qint64 nAddress, qint64 nMaxSize)
{
    return XProcess::read_ansiString(getProcessHandle(),nAddress,nMaxSize);
}

QString XDebugger::read_unicodeString(qint64 nAddress, qint64 nMaxSize)
{
    return XProcess::read_unicodeString(getProcessHandle(),nAddress,nMaxSize);
}

quint32 XDebugger::read_uint32(qint64 nAddress)
{
    return XProcess::read_uint32(getProcessHandle(),nAddress);
}

quint64 XDebugger::read_uint64(qint64 nAddress)
{
    return XProcess::read_uint64(getProcessHandle(),nAddress);
}

void XDebugger::write_uint32(qint64 nAddress, quint32 nValue)
{
    XProcess::write_uint32(getProcessHandle(),nAddress,nValue);
}

qint64 XDebugger::findSignature(qint64 nAddress, qint64 nSize, QString sSignature)
{
    qint64 nResult=-1;

    XProcessDevice xpd(this);

    if(xpd.openHandle(getProcessHandle(),nAddress,nSize,QIODevice::ReadOnly))
    {
        XBinary binary(&xpd,true,nAddress);

        qint64 nOffset=binary.find_signature(0,nSize,sSignature);
        nResult=binary.offsetToAddress(nOffset);

        xpd.close();
    }

    return nResult;
}

void XDebugger::skipFunction(HANDLE hThread, quint32 nNumberOfParameters, quint64 nResult)
{
#ifndef Q_OS_WIN64
        quint32 nESP=getRegister(hThread,REG_NAME_ESP);
        quint32 nRET=read_uint32(nESP);
        nESP+=4+4*nNumberOfParameters;
        setRegister(hThread,REG_NAME_ESP,nESP);
        setRegister(hThread,REG_NAME_EIP,nRET);
        setRegister(hThread,REG_NAME_EAX,(quint32)nResult);
#else
    qCritical("skipFunction");
    //        quint64 nRSP=getRegister_x86(UC_X86_REG_RSP);
    //        quint64 nRET=read_uint64(nRSP);
    //        int _nNumbersOfArgs=qMax(nNumberOfArgs-4,0);
    //        nRSP+=8+8*_nNumbersOfArgs;
    //        setRegister_x86(UC_X86_REG_RSP,nRSP);
    //        setRegister_x86(UC_X86_REG_RIP,nRET);
#endif
}

void XDebugger::stepInto(HANDLE hThread,QVariant vInfo)
{
    _setStep(hThread);
    stats.bStepInto=true;
    stats.vStepIntoInfo=vInfo;
}

void XDebugger::stop()
{
    // TODO errors
    TerminateProcess(getProcessHandle(),0);
}

bool XDebugger::dumpMemoryRegionToFile(QString sFilename, qint64 nAddress, qint64 nSize)
{
    bool bResult=false;

    XProcessDevice xpd(this);

    if(xpd.openHandle(getProcessHandle(),nAddress,nSize,QIODevice::ReadOnly))
    {
        XBinary binary(&xpd);

        bResult=binary.dumpToFile(sFilename,(qint64)0,nSize);

        xpd.close();
    }

    return bResult;
}

bool XDebugger::isAddressInImage(qint64 nAddress)
{
    bool bResult=false;

    if((targetInfo.nImageBase<=nAddress)&&(nAddress<targetInfo.nImageBase+targetInfo.nImageSize))
    {
        bResult=true;
    }

    return bResult;
}

QString XDebugger::getFunctionNameByAddress(qint64 nAddress)
{
    QString sResult;

    QMapIterator<qint64,DLL_INFO> i(mapDLL);

    while(i.hasNext())
    {
        i.next();

        DLL_INFO dllInfo=i.value();

        if((dllInfo.nImageBase<=nAddress)&&(nAddress<dllInfo.nImageBase+dllInfo.nImageSize))
        {
            XProcessDevice xpd(this);

            if(xpd.openHandle(getProcessHandle(),dllInfo.nImageBase,dllInfo.nImageSize,QIODevice::ReadOnly))
            {
                XPE pe(&xpd,true,dllInfo.nImageBase);

                if(pe.isValid())
                {
                    XPE::EXPORT_HEADER exportHeader=pe.getExport();

                    int nCount=exportHeader.listPositions.count();

                    for(int i=0;i<nCount;i++)
                    {
                        if(exportHeader.listPositions.at(i).nAddress==nAddress)
                        {
                            sResult=exportHeader.sName.toUpper()+"#"+exportHeader.listPositions.at(i).sFunctionName;
                            break;
                        }
                    }
                }

                xpd.close();
            }

            break;
        }
    }

    return sResult;
}

quint64 XDebugger::getRegister(HANDLE hThread, XDebugger::REG_NAME regName)
{
    qint64 nResult=0;

    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
#ifndef Q_OS_WIN64
        switch(regName)
        {
            case REG_NAME_EAX:  nResult=context.Eax;    break;
            case REG_NAME_EBX:  nResult=context.Ebx;    break;
            case REG_NAME_ECX:  nResult=context.Ebx;    break;
            case REG_NAME_EDX:  nResult=context.Edx;    break;
            case REG_NAME_ESI:  nResult=context.Esi;    break;
            case REG_NAME_EDI:  nResult=context.Edi;    break;
            case REG_NAME_EBP:  nResult=context.Ebp;    break;
            case REG_NAME_ESP:  nResult=context.Esp;    break;
            case REG_NAME_EIP:  nResult=context.Eip;    break;
        }
#else
        switch(regName)
        {
            case REG_NAME_RAX:  nResult=context.Rax;    break;
            case REG_NAME_RBX:  nResult=context.Rbx;    break;
            case REG_NAME_RCX:  nResult=context.Rbx;    break;
            case REG_NAME_RDX:  nResult=context.Rdx;    break;
            case REG_NAME_RSI:  nResult=context.Rsi;    break;
            case REG_NAME_RDI:  nResult=context.Rdi;    break;
            case REG_NAME_RBP:  nResult=context.Rbp;    break;
            case REG_NAME_RSP:  nResult=context.Rsp;    break;
            case REG_NAME_RIP:  nResult=context.Rip;    break;
        }
#endif
    }

    return nResult;
}

bool XDebugger::setRegister(HANDLE hThread, XDebugger::REG_NAME regName, quint64 nValue)
{
    bool bResult=false;

    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
#ifndef Q_OS_WIN64
        switch(regName)
        {
            case REG_NAME_EAX:  context.Eax=(quint32)nValue;    break;
            case REG_NAME_EBX:  context.Ebx=(quint32)nValue;    break;
            case REG_NAME_ECX:  context.Ebx=(quint32)nValue;    break;
            case REG_NAME_EDX:  context.Edx=(quint32)nValue;    break;
            case REG_NAME_ESI:  context.Esi=(quint32)nValue;    break;
            case REG_NAME_EDI:  context.Edi=(quint32)nValue;    break;
            case REG_NAME_EBP:  context.Ebp=(quint32)nValue;    break;
            case REG_NAME_ESP:  context.Esp=(quint32)nValue;    break;
            case REG_NAME_EIP:  context.Eip=(quint32)nValue;    break;
        }
#else
        switch(regName)
        {
            case REG_NAME_RAX:  context.Rax=(quint32)nValue;    break;
            case REG_NAME_RBX:  context.Rbx=(quint32)nValue;    break;
            case REG_NAME_RCX:  context.Rbx=(quint32)nValue;    break;
            case REG_NAME_RDX:  context.Rdx=(quint32)nValue;    break;
            case REG_NAME_RSI:  context.Rsi=(quint32)nValue;    break;
            case REG_NAME_RDI:  context.Rdi=(quint32)nValue;    break;
            case REG_NAME_RBP:  context.Rbp=(quint32)nValue;    break;
            case REG_NAME_RSP:  context.Rsp=(quint32)nValue;    break;
            case REG_NAME_RIP:  context.Rip=(quint32)nValue;    break;
        }
#endif
        if(SetThreadContext(hThread,&context))
        {
            bResult=true;
        }
    }

    return bResult;
}

XDebugger::TARGET_INFO *XDebugger::getTargetInfo()
{
    return &targetInfo;
}

XDebugger::FILE_INFO *XDebugger::getFileInfo()
{
    return &fileInfo;
}

void XDebugger::_clear()
{
    options={};
    nProcessId=0;
    createProcessInfo={};
    fileInfo={};
    targetInfo={};
    stats={};
    mapDLL.clear();
    mapBP.clear();
    mapThreads.clear();
}

bool XDebugger::_setIP(HANDLE hThread, qint64 nAddress)
{
    bool bResult=false;
    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
#ifndef Q_OS_WIN64
        context.Eip=nAddress;
#else
        context.Rip=nAddress;
#endif
        if(SetThreadContext(hThread,&context))
        {
            bResult=true;
        }
    }

    return bResult;
}

bool XDebugger::_setStep(HANDLE hThread)
{
    bool bResult=false;
    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
        if(!(context.EFlags&0x100))
        {
            context.EFlags|=0x100;
        }

        if(SetThreadContext(hThread,&context))
        {
            bResult=true;
        }
    }

    return bResult;
}

bool XDebugger::_loadFile(QString sFileName, XDebugger::LOAD_TYPE loadType, XDebugger::OPTIONS *pOptions)
{
    bool bSuccess=false;
    _clear();

    if(pOptions)
    {
        options=*pOptions;
    }

    qint32 nFlags=DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS|CREATE_SUSPENDED;

    if(!options.bShowWindow)
    {
        nFlags|=CREATE_NO_WINDOW;
    }

    PROCESS_INFORMATION processInfo= {};
    STARTUPINFOW sturtupInfo= {};

    // TODO 32/64
    sturtupInfo.cb=sizeof(sturtupInfo);

    BOOL _bCreateProcess=FALSE;

    QString _sFileName;
    QString _sArgument;

    QString sTargetMD5;

    if(loadType==LOAD_TYPE_EXE)
    {
        _sFileName=sFileName;
        _sArgument=QString("\"%1\" \"%2\"").arg(_sFileName).arg(options.sArgument);
        _bCreateProcess=CreateProcessW((const wchar_t*)_sFileName.utf16(),(wchar_t*)_sArgument.utf16(),nullptr,nullptr,0,nFlags,nullptr,nullptr,&sturtupInfo,&processInfo);
    }
    else if(loadType==LOAD_TYPE_DLL)
    {
        _sFileName=qApp->applicationDirPath()+QDir::separator()+"LibraryLoader32.exe"; // TODO 64
        _sArgument=QString("\"%1\" \"%2\"").arg(_sFileName).arg(sFileName);
        sTargetMD5=XBinary::getMD5(sFileName);
//        _sArgument=sFileName;
        _bCreateProcess=CreateProcessW((const wchar_t*)_sFileName.utf16(),(wchar_t*)_sArgument.utf16(),nullptr,nullptr,0,nFlags,nullptr,nullptr,&sturtupInfo,&processInfo);
    }

    if(_bCreateProcess)
    {
        nProcessId=processInfo.dwProcessId;

        if(ResumeThread(processInfo.hThread)!=((DWORD)-1))
        {
            BREAKPOINT bpRestore= {};
            bool bRestoreBP=false;
            QMap<quint64,FUNCTION_INFO> mapAPI;

            bool bLoaded=false;
            bool bTargetDLLLoaded=false;

            while(true)
            {
                DEBUG_EVENT DBGEvent= {0};
                WaitForDebugEvent(&DBGEvent, INFINITE);

                quint32 nStatus=DBG_CONTINUE;

                if(DBGEvent.dwProcessId==nProcessId)
                {
                    if(DBGEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)
                    {
                        createProcessInfo.hProcess=DBGEvent.u.CreateProcessInfo.hProcess;
                        createProcessInfo.hThread=DBGEvent.u.CreateProcessInfo.hThread;
                        createProcessInfo.nImageBase=(qint64)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                        createProcessInfo.nStartAddress=(qint64)DBGEvent.u.CreateProcessInfo.lpStartAddress;
                        createProcessInfo.sFileName=XProcess::getFileNameByHandle(DBGEvent.u.CreateProcessInfo.hFile);
                        createProcessInfo.nThreadLocalBase=(qint64)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;

                        if(loadType==LOAD_TYPE_EXE)
                        {
                            _getFileInfo(createProcessInfo.sFileName);

                            targetInfo.sFileName=createProcessInfo.sFileName;
                            targetInfo.nImageBase=createProcessInfo.nImageBase;
                            targetInfo.nImageSize=XProcess::getImageSize(getProcessHandle(),createProcessInfo.nImageBase);
                            targetInfo.nStartAddress=createProcessInfo.nStartAddress;
                        }

                        setBP(createProcessInfo.nStartAddress,BP_TYPE_CC,BP_INFO_PROCESS_ENTRYPOINT,1);

                        mapThreads.insert(XProcess::getThreadIDByHandle(createProcessInfo.hThread),DBGEvent.u.CreateProcessInfo.hThread);

                        onCreateProcessDebugEvent(&createProcessInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
                    {
                        CREATETHREAD_INFO createThreadInfo= {};

                        createThreadInfo.hThread=DBGEvent.u.CreateThread.hThread;
                        createThreadInfo.nStartAddress=(qint64)DBGEvent.u.CreateThread.lpStartAddress;
                        createThreadInfo.nThreadLocalBase=(qint64)DBGEvent.u.CreateThread.lpThreadLocalBase;

                        mapThreads.insert(XProcess::getThreadIDByHandle(DBGEvent.u.CreateThread.hThread),DBGEvent.u.CreateThread.hThread);

                        onCreateThreadDebugEvent(&createThreadInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)
                    {
                        EXITPROCESS_INFO exitProcessInfo= {};

                        exitProcessInfo.nExitCode=(qint32)DBGEvent.u.ExitProcess.dwExitCode;

                        mapThreads.remove(DBGEvent.dwThreadId);

                        onExitProcessDebugEvent(&exitProcessInfo);

                        break;
                    }
                    else if(DBGEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT)
                    {
                        EXITTHREAD_INFO exitThreadInfo= {};

                        exitThreadInfo.nExitCode=(qint32)DBGEvent.u.ExitThread.dwExitCode;

                        mapThreads.remove(DBGEvent.dwThreadId);

                        onExitThreadDebugEvent(&exitThreadInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT)
                    {
                        DLL_INFO dllInfo= {};
                        dllInfo.nImageBase=(qint64)DBGEvent.u.LoadDll.lpBaseOfDll;
                        dllInfo.nImageSize=XProcess::getImageSize(getProcessHandle(),dllInfo.nImageBase);
                        dllInfo.sFileName=XProcess::getFileNameByHandle(DBGEvent.u.LoadDll.hFile);
                        dllInfo.sName=QFileInfo(dllInfo.sFileName).fileName();

                        mapDLL.insert(dllInfo.nImageBase,dllInfo);

                        // Add hooks if needed
                        QSetIterator<QString> i(stAPIHooks);

                        while(i.hasNext())
                        {
                            QString sFunctionName=i.next();
                            _addAPIHook(dllInfo,sFunctionName);
                        }

                        onLoadDllDebugEvent(&dllInfo);

                        if((bLoaded)&&(!bTargetDLLLoaded))
                        {
                            QString _sTargetMD5=XBinary::getMD5(dllInfo.sFileName);

                            if(_sTargetMD5==sTargetMD5)
                            {
                                _getFileInfo(dllInfo.sFileName);

                                targetInfo.sFileName=dllInfo.sFileName;
                                targetInfo.nImageBase=dllInfo.nImageBase;
                                targetInfo.nImageSize=XProcess::getImageSize(getProcessHandle(),dllInfo.nImageBase);
                                targetInfo.nStartAddress=fileInfo.nAddressOfEntryPoint+targetInfo.nImageBase;

                                setBP(targetInfo.nStartAddress,BP_TYPE_CC,BP_INFO_TARGETDLL_ENTRYPOINT,1);

                                bTargetDLLLoaded=true;
                            }
                        }
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
                        EXCEPTION_DEBUG_INFO edi=DBGEvent.u.Exception;
                        qint64 nExceptionAddress=(qint64)edi.ExceptionRecord.ExceptionAddress;
                        quint32 nExceptionCode=(quint32)edi.ExceptionRecord.ExceptionCode;
                        HANDLE hThread=mapThreads.value(DBGEvent.dwThreadId);

                        nStatus=DBG_EXCEPTION_NOT_HANDLED;

                        if(nExceptionCode==EXCEPTION_BREAKPOINT)
                        {
                            if(mapBP.contains(nExceptionAddress))
                            {
                                // TODO multithreads
                                // Stop all another threads mb as options?
                                BREAKPOINT bp=mapBP.value(nExceptionAddress);
                                bp.hThread=hThread;

                                if(bp.nCount!=-1)
                                {
                                    bp.nCount--;
                                }

                                if(bp.nCount)
                                {
                                    bpRestore=bp;
                                    bRestoreBP=true;
                                }

                                _setIP(mapThreads.value(DBGEvent.dwThreadId),nExceptionAddress);

                                removeBP(nExceptionAddress);

                                if(bp.bpInfo==BP_INFO_PROCESS_ENTRYPOINT)
                                {
                                    bLoaded=true;

                                    ENTRYPOINT_INFO entryPointInfo= {};

                                    entryPointInfo.nAddress=nExceptionAddress;
                                    entryPointInfo.hThread=hThread;

                                    onProcessEntryPoint(&entryPointInfo);
                                    if(loadType==LOAD_TYPE_EXE)
                                    {
                                        onTargetEntryPoint(&entryPointInfo);
                                    }
                                }
                                else if(bp.bpInfo==BP_INFO_TARGETDLL_ENTRYPOINT)
                                {
                                    ENTRYPOINT_INFO entryPointInfo= {};

                                    entryPointInfo.nAddress=nExceptionAddress;
                                    entryPointInfo.hThread=hThread;

                                    if(loadType==LOAD_TYPE_DLL)
                                    {
                                        onTargetEntryPoint(&entryPointInfo);
                                    }
                                }
                                else if(bp.bpInfo==BP_INFO_API_ENTER)
                                {
                                    FUNCTION_INFO functionInfo= {};
                                    functionInfo.hThread=hThread;
                                    functionInfo.nAddress=bp.nAddress;
                                    functionInfo.nRetAddress=_getRetAddress(hThread);
                                    functionInfo.sName=bp.vInfo.toString();
                                    functionInfo.nStackFrame=(qint64)getRegister(functionInfo.hThread,REG_NAME_ESP);

                                    onFunctionEnter(&functionInfo);

                                    quint64 nID=XBinary::random64();
                                    mapAPI.insert(nID,functionInfo);

                                    setBP(functionInfo.nRetAddress,BP_TYPE_CC,BP_INFO_API_LEAVE,1,nID);
                                }
                                else if(bp.bpInfo==BP_INFO_API_LEAVE)
                                {
                                    quint64 nID=bp.vInfo.toULongLong();
                                    FUNCTION_INFO functionInfo=mapAPI.value(nID);

                                    onFunctionLeave(&functionInfo);
                                    mapAPI.remove(nID);
                                }
                                else
                                {
                                    onBreakPoint(&bp);
                                }

                                if(bRestoreBP)
                                {
                                    _setStep(mapThreads.value(DBGEvent.dwThreadId));
                                }

                                nStatus=DBG_CONTINUE;
                            }
                        }
                        else if(nExceptionCode==EXCEPTION_SINGLE_STEP)
                        {
                            if(bRestoreBP)
                            {
                                setBP(bpRestore.nAddress,bpRestore.bpType,bpRestore.bpInfo,bpRestore.nCount,bpRestore.vInfo);
                                bRestoreBP=false;
                                nStatus=DBG_CONTINUE;
                            }

                            if(stats.bStepInto)
                            {
                                STEP step={};

                                step.nAddress=nExceptionAddress;
                                step.hThread=hThread;
                                step.vInfo=stats.vStepIntoInfo;

                                stats.bStepInto=false;
                                stats.vStepIntoInfo.clear();

                                onStep(&step);

                                nStatus=DBG_CONTINUE;
                            }
                        }
                        else if(nExceptionCode==EXCEPTION_GUARD_PAGE)
                        {

                        }
                        else if(nExceptionCode==EXCEPTION_ACCESS_VIOLATION)
                        {

                        }
                        else if(nExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION)
                        {

                        }
                        else if(nExceptionCode==EXCEPTION_INT_DIVIDE_BY_ZERO)
                        {

                        }
                    }
                }

                ContinueDebugEvent(DBGEvent.dwProcessId,DBGEvent.dwThreadId,nStatus);
            }

            bSuccess=true;
        }
    }
    else
    {
        _messageString(MESSAGE_TYPE_ERROR,QString("%1: %2").arg(tr("Cannot load file")).arg(_sFileName));
    }

    return bSuccess;
}

void XDebugger::_getFileInfo(QString sFileName)
{
    QFile file;

    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadOnly))
    {
        XPE pe(&file);

        if(pe.isValid())
        {
            fileInfo.nMachine=pe.getFileHeader_Machine();
            fileInfo.nCharacteristics=pe.getFileHeader_Characteristics();
            fileInfo.nMagic=pe.getOptionalHeader_Magic();
            fileInfo.nSubsystem=pe.getOptionalHeader_Subsystem();
            fileInfo.nDllcharacteristics=pe.getOptionalHeader_DllCharacteristics();
            fileInfo.nMajorOperationSystemVersion=pe.getOptionalHeader_MajorOperatingSystemVersion();
            fileInfo.nMinorOperationSystemVersion=pe.getOptionalHeader_MinorOperatingSystemVersion();
            fileInfo.nImageBase=pe.getOptionalHeader_ImageBase();
            fileInfo.nResourceRVA=pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress;
            fileInfo.nResourceSize=pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE).Size;
            fileInfo.bIsTLSPresent=pe.isTLSPresent();
            fileInfo.nAddressOfEntryPoint=pe.getOptionalHeader_AddressOfEntryPoint();

            onFileLoad(&pe); // TODO move
        }

        file.close();
    }
}

void XDebugger::_messageString(XDebugger::MESSAGE_TYPE type, QString sText)
{
    emit messageString(type,sText);
}

qint64 XDebugger::_getRetAddress(HANDLE hThread)
{
    qint64 nResult=-1;

#ifndef Q_OS_WIN64
        quint64 nSP=getRegister(hThread,REG_NAME_ESP);
#else
        quint64 nSP=getRegister(hThread,REG_NAME_RSP);
#endif

    if(nSP!=(quint64)-1)
    {
#ifndef Q_OS_WIN64
        nResult=read_uint32((qint64)nSP);
#else
        nResult=read_uint64((qint64)nSP);
#endif
    }

    return nResult;
}
