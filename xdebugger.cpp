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

void XDebugger::setData(QString sFileName, XDebugger::OPTIONS *pOptions)
{
    d_sFileName=sFileName;
    d_pOptions=pOptions;
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

bool XDebugger::setBP(HANDLE hThread, qint64 nAddress,BP_TYPE bpType, BP_INFO bpInfo, qint32 nCount, QVariant vInfo)
{
    bool bResult=false;

    if(bpType==BP_TYPE_CC)
    {
        if(!mapBP_Instr.contains(nAddress))
        {
            BREAKPOINT_INSTR bpInstr={};
            bpInstr.nAddress=nAddress;
            bpInstr.nCount=nCount;
            bpInstr.bpInfo=bpInfo;
            bpInstr.bpType=bpType;
            bpInstr.vInfo=vInfo;

            bpInstr.nOrigDataSize=1;

            if(readData(nAddress,bpInstr.origData,bpInstr.nOrigDataSize))
            {
                if(writeData(nAddress,(char *)"\xCC",bpInstr.nOrigDataSize)) // TODO Check
                {
                    mapBP_Instr.insert(nAddress,bpInstr);

                    bResult=true;
                }
            }
        }
    }
    else if(bpType==BP_TYPE_HWEXE)
    {
        if(!mapBP_HW.contains(nAddress))
        {
            BREAKPOINT_HW bpHW={};
            bpHW.nAddress=nAddress;
            bpHW.nCount=nCount;
            bpHW.bpInfo=bpInfo;
            bpHW.bpType=bpType;
            bpHW.vInfo=vInfo;

            qint32 nIndex=_setHWBPX(hThread,nAddress,HWBP_ACCESS_EXECUTE,HWBP_SIZE_BYTE);

            if(nIndex!=-1)
            {
                bpHW.nIndex=nIndex;
                bpHW.hThread=hThread;

                mapBP_HW.insert(nAddress,bpHW);

                bResult=true;
            }
        }
    }

    return bResult;
}

bool XDebugger::removeBP(HANDLE hThread,qint64 nAddress,XDebugger::BP_TYPE bpType)
{
    bool bResult=false;

    if(bpType==BP_TYPE_CC)
    {
        if(mapBP_Instr.contains(nAddress))
        {
            BREAKPOINT_INSTR bpInstr=mapBP_Instr.value(nAddress);

            if(bpInstr.bpType==BP_TYPE_CC)
            {
                if(writeData(nAddress,bpInstr.origData,bpInstr.nOrigDataSize))
                {
                    mapBP_Instr.remove(nAddress);

                    bResult=true;
                }
            }
        }
    }
    else if(bpType==BP_TYPE_HWEXE)
    {
        if(mapBP_HW.contains(nAddress))
        {
            BREAKPOINT_HW bpHW=mapBP_HW.value(nAddress);

            if(_removeHWBPX(hThread,bpHW.nIndex))
            {
                mapBP_HW.remove(nAddress);

                bResult=true;
            }
        }
    }

    return bResult;
}

bool XDebugger::addAPIHook(HANDLE hThread,QString sFunctionName,BP_TYPE bpType)
{
    bool bResult=false;

    if(sFunctionName!="")
    {
        QMapIterator<qint64,DLL_INFO> i(mapDLL);

        while(i.hasNext())
        {
            i.next();

            DLL_INFO dllInfo=i.value();

            if(_addAPIHook(hThread,dllInfo,sFunctionName,bpType))
            {
                bResult=true;
            }
        }

        if(bResult)
        {
            if(!mapAPIHooks.contains(sFunctionName))
            {
                mapAPIHooks.insert(sFunctionName,bpType);
            }
        }
    }

    return bResult;
}

bool XDebugger::removeAPIHook(QString sFunctionName)
{
    if(sFunctionName!="")
    {
        {
            QMutableMapIterator<qint64,BREAKPOINT_INSTR> iInstr(mapBP_Instr);

            QList<BREAKPOINT_INSTR> listBPInstr;

            while(iInstr.hasNext())
            {
                iInstr.next();

                BREAKPOINT_INSTR bp=iInstr.value();

                if(bp.vInfo.toString()==sFunctionName)
                {
                    listBPInstr.append(bp);
                }
            }

            for(int i=0;i<listBPInstr.count();i++)
            {
                removeBP(0,listBPInstr.at(i).nAddress,listBPInstr.at(i).bpType);
            }
        }

        {
            QMutableMapIterator<qint64,BREAKPOINT_HW> iHW(mapBP_HW);

            QList<BREAKPOINT_HW> listBPHW;

            while(iHW.hasNext())
            {
                iHW.next();

                BREAKPOINT_HW bp=iHW.value();

                if(bp.vInfo.toString()==sFunctionName)
                {
                    listBPHW.append(bp);
                }
            }

            for(int i=0;i<listBPHW.count();i++)
            {
                removeBP(listBPHW.at(i).hThread,listBPHW.at(i).nAddress,listBPHW.at(i).bpType);
            }
        }

        if(mapAPIHooks.contains(sFunctionName))
        {
            mapAPIHooks.remove(sFunctionName);
        }
    }

    return true;
}

bool XDebugger::_addAPIHook(HANDLE hThread,XDebugger::DLL_INFO dllInfo, QString sFunctionName,BP_TYPE bpType)
{
    bool bResult=false;

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
                        bResult=setBP(hThread,exportHeader.listPositions.at(i).nAddress,bpType,BP_INFO_API_ENTER,-1,sFunctionName);

                        break;
                    }
                }
            }

            xpd.close();
        }
    }

    return bResult;
}

bool XDebugger::isAPIHook(QString sFunctionName)
{
    return mapAPIHooks.contains(sFunctionName);
}

quint64 XDebugger::getFunctionResult(XDebugger::FUNCTION_INFO *pFunctionInfo)
{
#ifndef Q_OS_WIN64
    return getRegister(pFunctionInfo->hThread,REG_NAME_EAX);
#else
    return getRegister(pFunctionInfo->hThread,REG_NAME_RAX);
#endif
}

quint64 XDebugger::getFunctionParameter(XDebugger::FUNCTION_INFO *pFunctionInfo, qint32 nNumber)
{
    quint64 nResult=0;

#ifndef Q_OS_WIN64
    qint64 _nStackAddress=pFunctionInfo->nStackFrame+4+4*nNumber;
    nResult=read_uint32(_nStackAddress);
#else
    // The Microsoft x64 calling convention
    if(nNumber==0)
    {
        nResult=getRegister(pFunctionInfo->hThread,REG_NAME_RCX);
    }
    else if(nNumber==1)
    {
        nResult=getRegister(pFunctionInfo->hThread,REG_NAME_RDX);
    }
    else if(nNumber==2)
    {
        nResult=getRegister(pFunctionInfo->hThread,REG_NAME_R8);
    }
    else if(nNumber==3)
    {
        nResult=getRegister(pFunctionInfo->hThread,REG_NAME_R9);
    }
    else
    {
        // TODO Check
        qint64 _nStackAddress=pFunctionInfo->nStackFrame+8+8*(nNumber-4);
        nResult=read_uint64(_nStackAddress);
    }
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

quint8 XDebugger::read_uint8(qint64 nAddress)
{
    return XProcess::read_uint8(getProcessHandle(),nAddress);
}

quint16 XDebugger::read_uint16(qint64 nAddress)
{
    return XProcess::read_uint16(getProcessHandle(),nAddress);
}

quint32 XDebugger::read_uint32(qint64 nAddress)
{
    return XProcess::read_uint32(getProcessHandle(),nAddress);
}

quint64 XDebugger::read_uint64(qint64 nAddress)
{
    return XProcess::read_uint64(getProcessHandle(),nAddress);
}

void XDebugger::write_uint8(qint64 nAddress, quint8 nValue)
{
    XProcess::write_uint8(getProcessHandle(),nAddress,nValue);
}

void XDebugger::write_uint16(qint64 nAddress, quint16 nValue)
{
    XProcess::write_uint16(getProcessHandle(),nAddress,nValue);
}

void XDebugger::write_uint32(qint64 nAddress, quint32 nValue)
{
    XProcess::write_uint32(getProcessHandle(),nAddress,nValue);
}

void XDebugger::write_uint64(qint64 nAddress, quint64 nValue)
{
    XProcess::write_uint64(getProcessHandle(),nAddress,nValue);
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
        quint64 nRSP=getRegister(hThread,REG_NAME_RSP);
        quint64 nRET=read_uint64(nRSP);
        int _nNumbersOfArgs=qMax((qint32)nNumberOfParameters-4,0);
        nRSP+=8+8*_nNumbersOfArgs;
        setRegister(hThread,REG_NAME_RSP,nRSP);
        setRegister(hThread,REG_NAME_RIP,nRET);
        setRegister(hThread,REG_NAME_RAX,(quint64)nResult);
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

void XDebugger::pause()
{
    QList<HANDLE> listThreads=mapThreads.values();

    int nCount=listThreads.count();

    for(int i=0;i<nCount;i++)
    {
        suspendThread(listThreads.at(i));
    }
}

void XDebugger::resume()
{
    QList<HANDLE> listThreads=mapThreads.values();

    int nCount=listThreads.count();

    for(int i=0;i<nCount;i++)
    {
        resumeThread(listThreads.at(i));
    }
}

void XDebugger::step()
{
    stepInto(stats.hBPThread);
}

void XDebugger::suspendThread(HANDLE hThread)
{
    SuspendThread(hThread);
}

void XDebugger::resumeThread(HANDLE hThread)
{
    ResumeThread(hThread);
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

bool XDebugger::isAddressInStack(qint64 nAddress)
{
    bool bResult=false;

    if((createProcessInfo.nStackAddress<=nAddress)&&(nAddress<createProcessInfo.nStackAddress+createProcessInfo.nStackSize))
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
            case REG_NAME_ECX:  nResult=context.Ecx;    break;
            case REG_NAME_EDX:  nResult=context.Edx;    break;
            case REG_NAME_ESI:  nResult=context.Esi;    break;
            case REG_NAME_EDI:  nResult=context.Edi;    break;
            case REG_NAME_EBP:  nResult=context.Ebp;    break;
            case REG_NAME_ESP:  nResult=context.Esp;    break;
            case REG_NAME_EIP:  nResult=context.Eip;    break;
            default:            qFatal("Unknown register");
        }
#else
        switch(regName)
        {
            case REG_NAME_RAX:  nResult=context.Rax;    break;
            case REG_NAME_RBX:  nResult=context.Rbx;    break;
            case REG_NAME_RCX:  nResult=context.Rcx;    break;
            case REG_NAME_RDX:  nResult=context.Rdx;    break;
            case REG_NAME_RSI:  nResult=context.Rsi;    break;
            case REG_NAME_RDI:  nResult=context.Rdi;    break;
            case REG_NAME_RBP:  nResult=context.Rbp;    break;
            case REG_NAME_RSP:  nResult=context.Rsp;    break;
            case REG_NAME_RIP:  nResult=context.Rip;    break;
            case REG_NAME_R8:   nResult=context.R8;     break;
            case REG_NAME_R9:   nResult=context.R9;     break;
            case REG_NAME_R10:  nResult=context.R10;    break;
            case REG_NAME_R11:  nResult=context.R11;    break;
            case REG_NAME_R12:  nResult=context.R12;    break;
            case REG_NAME_R13:  nResult=context.R13;    break;
            case REG_NAME_R14:  nResult=context.R14;    break;
            case REG_NAME_R15:  nResult=context.R15;    break;
            default:            qFatal("Unknown register");
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
            default:            qFatal("Unknown register");
        }
#else
        switch(regName)
        {
            case REG_NAME_RAX:  context.Rax=(quint64)nValue;    break;
            case REG_NAME_RBX:  context.Rbx=(quint64)nValue;    break;
            case REG_NAME_RCX:  context.Rbx=(quint64)nValue;    break;
            case REG_NAME_RDX:  context.Rdx=(quint64)nValue;    break;
            case REG_NAME_RSI:  context.Rsi=(quint64)nValue;    break;
            case REG_NAME_RDI:  context.Rdi=(quint64)nValue;    break;
            case REG_NAME_RBP:  context.Rbp=(quint64)nValue;    break;
            case REG_NAME_RSP:  context.Rsp=(quint64)nValue;    break;
            case REG_NAME_RIP:  context.Rip=(quint64)nValue;    break;
            case REG_NAME_R8:   context.R8=(quint64)nValue;     break;
            case REG_NAME_R9:   context.R9=(quint64)nValue;    break;
            case REG_NAME_R10:  context.R10=(quint64)nValue;    break;
            case REG_NAME_R11:  context.R11=(quint64)nValue;    break;
            case REG_NAME_R12:  context.R12=(quint64)nValue;    break;
            case REG_NAME_R13:  context.R13=(quint64)nValue;    break;
            case REG_NAME_R14:  context.R14=(quint64)nValue;    break;
            case REG_NAME_R15:  context.R15=(quint64)nValue;    break;
            default:            qFatal("Unknown register");
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
    mapBP_Instr.clear();
    mapThreads.clear();
}

void XDebugger::onFileLoad(XBinary *pBinary)
{
    emit _onFileLoad(pBinary);
}

void XDebugger::onCreateThreadDebugEvent(XDebugger::CREATETHREAD_INFO *pCreateThreadInfo)
{
    emit _onCreateThreadDebugEvent(pCreateThreadInfo);
}

void XDebugger::onTargetEntryPoint(XDebugger::ENTRYPOINT_INFO *pEntryPointInfo)
{
    emit _onTargetEntryPoint(pEntryPointInfo);
}

void XDebugger::onStep(XDebugger::STEP_INFO *pStepInfo)
{
    emit _onStep(pStepInfo);
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

    PROCESS_INFORMATION processInfo={};
    STARTUPINFOW sturtupInfo={};

    // TODO 32/64 !!! do not load if not the same(WOW64)
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
#ifndef Q_OS_WIN64
        _sFileName=qApp->applicationDirPath()+QDir::separator()+"LibraryLoader32.exe";
#else
        _sFileName=qApp->applicationDirPath()+QDir::separator()+"LibraryLoader64.exe";
#endif
        _sArgument=QString("\"%1\" \"%2\"").arg(_sFileName).arg(sFileName);
        sTargetMD5=XBinary::getHash(XBinary::HASH_MD5,sFileName);
//        _sArgument=sFileName;
        _bCreateProcess=CreateProcessW((const wchar_t*)_sFileName.utf16(),(wchar_t*)_sArgument.utf16(),nullptr,nullptr,0,nFlags,nullptr,nullptr,&sturtupInfo,&processInfo);
    }

    if(_bCreateProcess)
    {
        nProcessId=processInfo.dwProcessId;

        if(ResumeThread(processInfo.hThread)!=((DWORD)-1))
        {
            BREAKPOINT_INSTR bpRestoreInstr={};
            bool bRestoreBPInstr=false;
            BREAKPOINT_HW bpRestoreHW={};
            bool bRestoreBPHW=false;

            stats.bProcessEP=false;
            stats.bTargetDLLLoaded=false;

//            DWORD dwMainThreadID=0;

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

                #ifndef Q_OS_WIN64
                        quint32 nSP=getRegister(createProcessInfo.hThread,REG_NAME_ESP);
                #else
                        quint64 nSP=getRegister(createProcessInfo.hThread,REG_NAME_RSP);
                #endif
                        createProcessInfo.nStackAddress=XProcess::getRegionAllocationBase(getProcessHandle(),nSP);
                        createProcessInfo.nStackSize=XProcess::getRegionAllocationSize(getProcessHandle(),createProcessInfo.nStackAddress);

                        if(loadType==LOAD_TYPE_EXE)
                        {
                            _getFileInfo(createProcessInfo.sFileName);

                            targetInfo.sFileName=createProcessInfo.sFileName;
                            targetInfo.nImageBase=createProcessInfo.nImageBase;
                            targetInfo.nImageSize=XProcess::getRegionAllocationSize(getProcessHandle(),createProcessInfo.nImageBase);
                            targetInfo.nStartAddress=createProcessInfo.nStartAddress;
                        }

                        setBP(createProcessInfo.hThread,createProcessInfo.nStartAddress,BP_TYPE_HWEXE,BP_INFO_PROCESS_ENTRYPOINT,1);

                        mapThreads.insert(XProcess::getThreadIDByHandle(createProcessInfo.hThread),DBGEvent.u.CreateProcessInfo.hThread);

//                        dwMainThreadID=DBGEvent.dwThreadId;

                        onCreateProcessDebugEvent(&createProcessInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
                    {
                        CREATETHREAD_INFO createThreadInfo={};

                        createThreadInfo.hThread=DBGEvent.u.CreateThread.hThread;
                        createThreadInfo.nStartAddress=(qint64)DBGEvent.u.CreateThread.lpStartAddress;
                        createThreadInfo.nThreadLocalBase=(qint64)DBGEvent.u.CreateThread.lpThreadLocalBase;

                        mapThreads.insert(XProcess::getThreadIDByHandle(DBGEvent.u.CreateThread.hThread),DBGEvent.u.CreateThread.hThread);

                        onCreateThreadDebugEvent(&createThreadInfo);
                    }
                    else if(DBGEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)
                    {
                        EXITPROCESS_INFO exitProcessInfo={};

                        exitProcessInfo.nExitCode=(qint32)DBGEvent.u.ExitProcess.dwExitCode;

                        mapThreads.remove(DBGEvent.dwThreadId);

                        onExitProcessDebugEvent(&exitProcessInfo);

                        break;
                    }
                    else if(DBGEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT)
                    {
                        EXITTHREAD_INFO exitThreadInfo={};

                        exitThreadInfo.nExitCode=(qint32)DBGEvent.u.ExitThread.dwExitCode;

                        mapThreads.remove(DBGEvent.dwThreadId);

                        onExitThreadDebugEvent(&exitThreadInfo);

                        // Mb TODO exit main thread
                    }
                    else if(DBGEvent.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT)
                    {
                        DLL_INFO dllInfo={};
                        dllInfo.nImageBase=(qint64)DBGEvent.u.LoadDll.lpBaseOfDll;
                        dllInfo.nImageSize=XProcess::getRegionAllocationSize(getProcessHandle(),dllInfo.nImageBase);
                        dllInfo.sFileName=XProcess::getFileNameByHandle(DBGEvent.u.LoadDll.hFile);
                        dllInfo.sName=QFileInfo(dllInfo.sFileName).fileName();

                        HANDLE hThread=mapThreads.value(DBGEvent.dwThreadId);

                        mapDLL.insert(dllInfo.nImageBase,dllInfo);

                        // Add hooks if needed
                        QMapIterator<QString,BP_TYPE> i(mapAPIHooks);

                        while(i.hasNext())
                        {
                            i.next();

                            QString sFunctionName=i.key();
                            BP_TYPE bpType=i.value();
                            _addAPIHook(hThread,dllInfo,sFunctionName,bpType);
                        }

                        onLoadDllDebugEvent(&dllInfo);

                        if((stats.bProcessEP)&&(!stats.bTargetDLLLoaded))
                        {
                            QString _sTargetMD5=XBinary::getHash(XBinary::HASH_MD5,dllInfo.sFileName);

                            if(_sTargetMD5==sTargetMD5)
                            {
                                _getFileInfo(dllInfo.sFileName);

                                targetInfo.sFileName=dllInfo.sFileName;
                                targetInfo.nImageBase=dllInfo.nImageBase;
                                targetInfo.nImageSize=XProcess::getRegionAllocationSize(getProcessHandle(),dllInfo.nImageBase);
                                targetInfo.nStartAddress=fileInfo.nAddressOfEntryPoint+targetInfo.nImageBase;

                                setBP(hThread,targetInfo.nStartAddress,BP_TYPE_HWEXE,BP_INFO_TARGETDLL_ENTRYPOINT,1);

                                stats.bTargetDLLLoaded=true;
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
//                        bool bIsFirtsChance=(edi.dwFirstChance==1);
                        // TODO Exceptions in TLS
//                        qDebug("Exception: %x",nExceptionAddress);
//                        qDebug("ExceptionCode: %x",nExceptionCode);

                        nStatus=DBG_EXCEPTION_NOT_HANDLED;

                        if((nExceptionCode==EXCEPTION_BREAKPOINT)||(nExceptionCode==0x4000001f )) // 4000001f WOW64 breakpoint
                        {
                            if(mapBP_Instr.contains(nExceptionAddress))
                            {
                                stats.hBPThread=hThread;

                                bool bThreadsSuspended=_suspendOtherThreads(hThread);

                                BREAKPOINT_INSTR bpCC=mapBP_Instr.value(nExceptionAddress);

                                if(bpCC.nCount!=-1)
                                {
                                    bpCC.nCount--;
                                }

                                if(bpCC.nCount)
                                {
                                    bpRestoreInstr=bpCC;
                                    bRestoreBPInstr=true;
                                }

                                _setIP(mapThreads.value(DBGEvent.dwThreadId),nExceptionAddress);

                                removeBP(hThread,nExceptionAddress,bpCC.bpType);

                                _handleBP(loadType,bpCC.bpInfo,bpCC.nAddress,hThread,bpCC.bpType,bpCC.vInfo);

                                if(bRestoreBPInstr)
                                {
                                    _setStep(hThread);
                                }

                                if(bThreadsSuspended)
                                {
                                    _resumeOtherThreads(hThread);
                                }

                                nStatus=DBG_CONTINUE;
                            }
                            else
                            {

                            }
                        }
                        else if((nExceptionCode==EXCEPTION_SINGLE_STEP)||(nExceptionCode==0x4000001e)) // 4000001e WOW64 single step exception
                        {
                            if(bRestoreBPInstr)
                            {
                                setBP(hThread,bpRestoreInstr.nAddress,bpRestoreInstr.bpType,bpRestoreInstr.bpInfo,bpRestoreInstr.nCount,bpRestoreInstr.vInfo);
                                bRestoreBPInstr=false;
                                nStatus=DBG_CONTINUE;
                            }

                            if(bRestoreBPHW)
                            {
                                setBP(hThread,bpRestoreHW.nAddress,bpRestoreHW.bpType,bpRestoreHW.bpInfo,bpRestoreHW.nCount,bpRestoreHW.vInfo);
                                bRestoreBPHW=false;
                                nStatus=DBG_CONTINUE;
                            }

                            bool bThreadsSuspended=false;

                            if(stats.bStepInto)
                            {
                                stats.hBPThread=hThread;
                                bThreadsSuspended=_suspendOtherThreads(hThread);

                                STEP_INFO stepInfo={};

                                stepInfo.nAddress=nExceptionAddress;
                                stepInfo.hThread=hThread;
                                stepInfo.vInfo=stats.vStepIntoInfo;

                                stats.bStepInto=false;
                                stats.vStepIntoInfo.clear();

                                onStep(&stepInfo);

                                nStatus=DBG_CONTINUE;
                            }

                            // Check HW
                            DBGREGS dr={};
                            if(_getDbgRegs(hThread,&dr))
                            {
                                for(int i=0; i<4; i++)
                                {
                                    if(dr.nStatus&((quint64)1<<i))
                                    {
                                        qint64 nBPAddress=dr.regs[i];

                                        if(mapBP_HW.contains(nBPAddress))
                                        {
                                            if(!bThreadsSuspended) // If StepInto
                                            {
                                                bThreadsSuspended=_suspendOtherThreads(hThread);
                                            }

                                            BREAKPOINT_HW bpHW=mapBP_HW.value(nBPAddress);

                                            if(i==bpHW.nIndex)
                                            {
                                                stats.hBPThread=hThread;

                                                if(bpHW.nCount!=-1)
                                                {
                                                    bpHW.nCount--;
                                                }

                                                if(bpHW.nCount)
                                                {
                                                    bpRestoreHW=bpHW;
                                                    bRestoreBPHW=true;
                                                }

                                                removeBP(hThread,nBPAddress,bpHW.bpType);

                                                _handleBP(loadType,bpHW.bpInfo,bpHW.nAddress,hThread,bpHW.bpType,bpHW.vInfo);

                                                if(bRestoreBPHW)
                                                {
                                                    _setStep(hThread);
                                                }

                                                nStatus=DBG_CONTINUE;
                                            }
                                        }

                                        break;
                                    }
                                }
                            }

                            if(bThreadsSuspended)
                            {
                                _resumeOtherThreads(hThread);
                            }
                        }
                        else if(nExceptionCode==EXCEPTION_GUARD_PAGE)
                        {

                        }
                        else if(nExceptionCode==EXCEPTION_ACCESS_VIOLATION)
                        {
                            qDebug("EXCEPTION_ACCESS_VIOLATION");
                        }
                        else if(nExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION)
                        {

                        }
                        else if(nExceptionCode==EXCEPTION_INT_DIVIDE_BY_ZERO)
                        {

                        }

                        if(nStatus!=DBG_CONTINUE)
                        {
                            if(stats.bProcessEP)
                            {
                                EXCEPTION_INFO exceptionInfo={};
                                exceptionInfo.nAddress=_getCurrentAddress(hThread);
                                exceptionInfo.nExceptionCode=edi.ExceptionRecord.ExceptionCode;
                                exceptionInfo.nExceptionAddress=(qint64)edi.ExceptionRecord.ExceptionAddress;

                                onException(&exceptionInfo);

                            #ifndef Q_OS_WIN64
                                qint64 nTEBAddress=XProcess::getTEBAddress(hThread);

                                quint32 nSEHAddress=read_uint32(nTEBAddress);

                                if(nSEHAddress!=-1)
                                {
                                    qint64 nCodeAddress=read_uint32(nSEHAddress+4);
                                    setBP(hThread,nCodeAddress,BP_TYPE_CC,BP_INFO_SEH,1);
                                }
                            #endif
                            }
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
            fileInfo.bIs64=pe.is64();

            onFileLoad(&pe); // TODO move
        }

        file.close();
    }
}

void XDebugger::_handleBP(LOAD_TYPE loadType,BP_INFO bpInfo, qint64 nAddress, HANDLE hThread,BP_TYPE bpType,QVariant vInfo)
{
    if(bpInfo==BP_INFO_PROCESS_ENTRYPOINT)
    {
        stats.bProcessEP=true;

        ENTRYPOINT_INFO entryPointInfo={};

        entryPointInfo.nAddress=nAddress;
        entryPointInfo.hThread=hThread;

        onProcessEntryPoint(&entryPointInfo);
        if(loadType==LOAD_TYPE_EXE)
        {
            onTargetEntryPoint(&entryPointInfo);
        }
    }
    else if(bpInfo==BP_INFO_TARGETDLL_ENTRYPOINT)
    {
        ENTRYPOINT_INFO entryPointInfo={};

        entryPointInfo.nAddress=nAddress;
        entryPointInfo.hThread=hThread;

        if(loadType==LOAD_TYPE_DLL)
        {
            onTargetEntryPoint(&entryPointInfo);
        }
    }
    else if(bpInfo==BP_INFO_API_ENTER)
    {
        FUNCTION_INFO functionInfo={};
        functionInfo.hThread=hThread;
        functionInfo.nAddress=nAddress;
        functionInfo.nRetAddress=_getRetAddress(hThread);
        functionInfo.sName=vInfo.toString();
#ifndef Q_OS_WIN64
        functionInfo.nStackFrame=(qint64)getRegister(functionInfo.hThread,REG_NAME_ESP);
#else
        functionInfo.nStackFrame=(qint64)getRegister(functionInfo.hThread,REG_NAME_RSP);
#endif
        onFunctionEnter(&functionInfo);

        quint64 nID=XBinary::random64();
        stats.mapAPI.insert(nID,functionInfo);

        if(!setBP(hThread,functionInfo.nRetAddress,bpType,BP_INFO_API_LEAVE,1,nID))
        {
            qFatal("Cannot set BP_INFO_API_LEAVE");
        }
    }
    else if(bpInfo==BP_INFO_API_LEAVE)
    {
        quint64 nID=vInfo.toULongLong();
        FUNCTION_INFO functionInfo=stats.mapAPI.value(nID);

        onFunctionLeave(&functionInfo);
        stats.mapAPI.remove(nID);
    }
    else if(bpInfo==BP_INFO_SEH)
    {
        SEH_INFO sehInfo={};

        sehInfo.nAddress=_getCurrentAddress(hThread);
        sehInfo.hThread=hThread;

        onSEH(&sehInfo);
    }
    else
    {
        BREAKPOINT_INFO breakPointInfo={};

        breakPointInfo.nAddress=nAddress;
        breakPointInfo.bpInfo=bpInfo;
        breakPointInfo.bpType=bpType;
        breakPointInfo.vInfo=vInfo;
        breakPointInfo.hThread=hThread;

        onBreakPoint(&breakPointInfo);
    }
}

qint32 XDebugger::_setHWBPX(HANDLE hThread,qint64 nAddress, XDebugger::HWBP_ACCESS access, XDebugger::HWBP_SIZE size)
{
    qint64 nCurrentIndex=-1;

    DBGREGS dr={};

    if(_getDbgRegs(hThread,&dr))
    {
        // Get Free index
        for(int i=0; i<4; i++)
        {
            if(!(dr.nControl&(((quint64)1)<<(i*2))))
            {
                nCurrentIndex=i;
                break;
            }
        }

        if(nCurrentIndex!=-1)
        {
            dr.regs[nCurrentIndex]=nAddress;

            quint64 _Ctrl=0;
            quint64 _Size=0;

            switch(access)
            {
                case HWBP_ACCESS_EXECUTE:
                    _Ctrl=0;
                    break;

                case HWBP_ACCESS_READ:
                    _Ctrl=1;
                    break;

                case HWBP_ACCESS_READWRITE:
                    _Ctrl=3;
                    break;
            }

            switch(size)
            {
                case HWBP_SIZE_BYTE:
                    _Size=0;
                    break;

                case HWBP_SIZE_WORD:
                    _Size=1;
                    break;

                case HWBP_SIZE_QWORD:
                    _Size=2;
                    break;

                case HWBP_SIZE_DWORD:
                    _Size=3;
                    break;
            }

            dr.nControl|=(((quint64)1)<<(nCurrentIndex*2));
            dr.nControl|=((_Ctrl+(_Size<<2))<<(16+nCurrentIndex*2));
            dr.nControl&=0xFFFF03FF;
            // if Bit 10 set on 64 clear DR2

            dr.nStatus=0;

            if(!_setDbgRegs(hThread,&dr))
            {
                nCurrentIndex=-1;
            }
        }
    }

    return nCurrentIndex;
}

bool XDebugger::_removeHWBPX(HANDLE hThread, qint32 nIndex)
{
    bool bResult=false;

    if((quint32)nIndex<4)
    {
        DBGREGS dr={};

        if(_getDbgRegs(hThread,&dr))
        {
            dr.regs[nIndex]=0;

            dr.nControl&=~(((quint64)0x3)<<(nIndex*2));
            dr.nControl&=~(((quint64)0xF)<<(16+nIndex*4));

            dr.nStatus=0;

            if(_setDbgRegs(hThread,&dr))
            {
                bResult=true;
            }
        }
    }

    return bResult;
}

bool XDebugger::_setDbgRegs(HANDLE hThread,XDebugger::DBGREGS *pDr)
{
    bool bResult=false;

    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
        context.Dr0=pDr->regs[0];
        context.Dr1=pDr->regs[1];
        context.Dr2=pDr->regs[2];
        context.Dr3=pDr->regs[3];
        context.Dr6=pDr->nStatus;
        context.Dr7=pDr->nControl;

        bResult=SetThreadContext(hThread,&context);
    }

    return bResult;
}

bool XDebugger::_getDbgRegs(HANDLE hThread, XDebugger::DBGREGS *pDr)
{
    bool bResult=false;

    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
        pDr->regs[0]=context.Dr0;
        pDr->regs[1]=context.Dr1;
        pDr->regs[2]=context.Dr2;
        pDr->regs[3]=context.Dr3;
        pDr->nStatus=context.Dr6;
        pDr->nControl=context.Dr7;

        bResult=true;
    }

    return bResult;
}

bool XDebugger::_suspendOtherThreads(HANDLE hCurrentThread)
{
    bool bResult=false;

    QList<HANDLE> listThreads=mapThreads.values();

    int nCount=listThreads.count();

    // Suspend all other threads
    for(int i=0;i<nCount;i++)
    {
        if(hCurrentThread!=listThreads.at(i))
        {
            suspendThread(listThreads.at(i));

            bResult=true;
        }
    }

    return bResult;
}

bool XDebugger::_resumeOtherThreads(HANDLE hCurrentThread)
{
    bool bResult=false;

    QList<HANDLE> listThreads=mapThreads.values();

    int nCount=listThreads.count();

    // Resume all other threads
    for(int i=0;i<nCount;i++)
    {
        if(hCurrentThread!=listThreads.at(i))
        {
            resumeThread(listThreads.at(i));

            bResult=true;
        }
    }

    return bResult;
}

void XDebugger::process()
{
    loadFile(d_sFileName,d_pOptions);

    emit finished();
}

void XDebugger::continueExecution()
{
    emit _continueExecution();
}

void XDebugger::_messageString(XDebugger::MESSAGE_TYPE type, QString sText)
{
    emit messageString(type,sText);
}

QMap<XDebugger::REG_NAME, quint64> XDebugger::_getRegState(HANDLE hThread)
{
    QMap<XDebugger::REG_NAME, quint64> mapResult;

    CONTEXT context= {0};
    context.ContextFlags=CONTEXT_ALL;

    if(GetThreadContext(hThread,&context))
    {
#ifndef Q_OS_WIN64
        mapResult.insert(REG_NAME_EAX,context.Eax);
        mapResult.insert(REG_NAME_EAX,context.Ebx);
        mapResult.insert(REG_NAME_EAX,context.Ecx);
        mapResult.insert(REG_NAME_EAX,context.Edx);
        mapResult.insert(REG_NAME_EAX,context.Esi);
        mapResult.insert(REG_NAME_EAX,context.Edi);
        mapResult.insert(REG_NAME_EAX,context.Ebp);
        mapResult.insert(REG_NAME_EAX,context.Esp);
        mapResult.insert(REG_NAME_EAX,context.Eip);
        mapResult.insert(REG_NAME_EAX,context.EFlags);
#else
        mapResult.insert(REG_NAME_EAX,context.Rax);
        mapResult.insert(REG_NAME_EAX,context.Rbx);
        mapResult.insert(REG_NAME_EAX,context.Rcx);
        mapResult.insert(REG_NAME_EAX,context.Rdx);
        mapResult.insert(REG_NAME_EAX,context.Rsi);
        mapResult.insert(REG_NAME_EAX,context.Rdi);
        mapResult.insert(REG_NAME_EAX,context.Rbp);
        mapResult.insert(REG_NAME_EAX,context.Rsp);
        mapResult.insert(REG_NAME_EAX,context.Rip);
        // TODO more regs
        mapResult.insert(REG_NAME_EAX,context.EFlags);
#endif
    }

    return mapResult;
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

qint64 XDebugger::_getCurrentAddress(HANDLE hThread)
{
    qint64 nResult=-1;

#ifndef Q_OS_WIN64
    nResult=getRegister(hThread,REG_NAME_EIP);
#else
    nResult=getRegister(hThread,REG_NAME_RIP);
#endif

    return nResult;
}
