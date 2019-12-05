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
#ifndef XDEBUGGER_H
#define XDEBUGGER_H

#include <QCoreApplication>
#include <QObject>
#include <QMap>
#include <QFileInfo>
#include "windows.h"
#include "xprocess.h"
#include "xprocessdevice.h"
#include "xpe.h"

class XDebugger : public QObject
{
    Q_OBJECT

public:
    struct OPTIONS
    {
        bool bShowWindow;
        QString sArgument;
    };

    enum MESSAGE_TYPE
    {
        MESSAGE_TYPE_UNKNOWN=0,
        MESSAGE_TYPE_INFO,
        MESSAGE_TYPE_WARNING,
        MESSAGE_TYPE_ERROR
    };

    struct DLL_INFO
    {
        QString sName;
        QString sFileName;
        qint64 nImageBase;
        qint64 nImageSize;
    };

    struct FUNCTION_INFO
    {
        qint64 nAddress;
        qint64 nRetAddress;
        QString sName;
        HANDLE hThread;
        qint64 nStackFrame;
    };

    struct SEH_INFO
    {
        qint64 nAddress;
        HANDLE hThread;
    };

    explicit XDebugger(QObject *parent=nullptr);
    void setData(QString sFileName,OPTIONS *pOptions);
    bool loadFile(QString sFileName,OPTIONS *pOptions=nullptr);
    HANDLE getProcessHandle();
    QMap<qint64,DLL_INFO> *getMapDLL();
    quint64 getFunctionResult(FUNCTION_INFO *pFunctionInfo);
    quint64 getFunctionParameter(FUNCTION_INFO *pFunctionInfo,qint32 nNumber); // TODO call conversions
    bool readData(qint64 nAddress,char *pBuffer,qint32 nBufferSize);
    bool writeData(qint64 nAddress,char *pBuffer,qint32 nBufferSize);
    QByteArray read_array(qint64 nAddress,qint32 nSize);
    QString read_ansiString(qint64 nAddress,qint64 nMaxSize=256);
    QString read_unicodeString(qint64 nAddress,qint64 nMaxSize=256);
    quint8 read_uint8(qint64 nAddress);
    quint16 read_uint16(qint64 nAddress);
    quint32 read_uint32(qint64 nAddress);
    quint64 read_uint64(qint64 nAddress);
    void write_uint8(qint64 nAddress,quint8 nValue);
    void write_uint16(qint64 nAddress,quint16 nValue);
    void write_uint32(qint64 nAddress,quint32 nValue);
    void write_uint64(qint64 nAddress,quint64 nValue);

    qint64 findSignature(qint64 nAddress, qint64 nSize, QString sSignature);
    void skipFunction(HANDLE hThread, quint32 nNumberOfParameters,quint64 nResult);
    void stepInto(HANDLE hThread,QVariant vInfo=QVariant());

    void stop();
    void pause();
    void resume();
    void stepInto();
    void stepOver();
    void suspendThread(HANDLE hThread);
    void resumeThread(HANDLE hThread);

    bool dumpMemoryRegionToFile(QString sFilename,qint64 nAddress,qint64 nSize);
    bool isAddressInImage(qint64 nAddress);
    bool isAddressInStack(qint64 nAddress);

    struct FILE_INFO
    {
        quint16 nMachine;
        quint16 nCharacteristics;
        quint16 nMagic;
        quint16 nSubsystem;
        quint16 nDllcharacteristics;
        quint8 nMajorOperationSystemVersion;
        quint8 nMinorOperationSystemVersion;
        quint64 nImageBase;
        quint32 nResourceRVA;
        quint32 nResourceSize;
        bool bIsTLSPresent;
        quint32 nAddressOfEntryPoint;
        bool bIs64;
    };

    struct TARGET_INFO
    {
        QString sFileName;
        qint64 nImageBase;
        qint64 nImageSize;
        qint64 nStartAddress;
    };

    struct CREATEPROCESS_INFO
    {
        HANDLE hProcess;
        HANDLE hThread;
        QString sFileName;
        qint64 nImageBase;
        qint64 nStartAddress;
        qint64 nThreadLocalBase;
        qint64 nStackAddress;
        qint64 nStackSize;
    };
    struct STATS
    {
        bool bProcessEP;
        bool bTargetDLLLoaded;
        bool bStepInto;
        QVariant vStepIntoInfo;
        QMap<quint64,FUNCTION_INFO> mapAPI;
        HANDLE hBPThread;
    };

    struct CREATETHREAD_INFO
    {
        HANDLE hThread;
        qint64 nThreadLocalBase;
        qint64 nStartAddress;
    };

    struct EXITPROCESS_INFO
    {
        qint32 nExitCode;
    };

    struct EXITTHREAD_INFO
    {
        qint32 nExitCode;
    };

    struct ENTRYPOINT_INFO
    {
        qint64 nAddress;
        HANDLE hThread;
    };

    enum BP_TYPE
    {
        BP_TYPE_UNKNOWN=0,
        BP_TYPE_CC,
        BP_TYPE_HWEXE
    };

    enum BP_INFO
    {
        BP_INFO_UNKNOWN=0,
        BP_INFO_PROCESS_ENTRYPOINT,
        BP_INFO_TARGETDLL_ENTRYPOINT,
        BP_INFO_API_ENTER,
        BP_INFO_API_LEAVE,
        BP_INFO_SEH,
        BP_INFO_USER
    };

    struct BREAKPOINT_INSTR
    {
        qint64 nAddress;
        qint32 nCount;
        BP_TYPE bpType;
        BP_INFO bpInfo;
        QVariant vInfo;
        char origData[4];
        qint32 nOrigDataSize;
    };

    struct BREAKPOINT_HW
    {
        qint64 nAddress;
        qint32 nCount;
        BP_TYPE bpType;
        BP_INFO bpInfo;
        QVariant vInfo;
        HANDLE hThread;
        qint32 nIndex;
    };

    struct STEP_INFO
    {
        qint64 nAddress;
        HANDLE hThread;
        QVariant vInfo;
    };

    struct EXCEPTION_INFO
    {
        qint64 nAddress;
        qint64 nExceptionAddress;
        qint32 nExceptionCode;
    };

    struct BREAKPOINT_INFO
    {
        qint64 nAddress;
        HANDLE hThread;
        BP_TYPE bpType;
        BP_INFO bpInfo;
        QVariant vInfo;
    };

protected:
    virtual void _clear();
    virtual void onFileLoad(XBinary *pBinary);
    virtual void onCreateProcessDebugEvent(CREATEPROCESS_INFO *pCreateProcessInfo)  {Q_UNUSED(pCreateProcessInfo)}
    virtual void onCreateThreadDebugEvent(CREATETHREAD_INFO *pCreateThreadInfo);
    virtual void onExitProcessDebugEvent(EXITPROCESS_INFO *pExitProcessInfo)        {Q_UNUSED(pExitProcessInfo)}
    virtual void onExitThreadDebugEvent(EXITTHREAD_INFO *pExitThreadInfo)           {Q_UNUSED(pExitThreadInfo)}
    virtual void onLoadDllDebugEvent(DLL_INFO *pDllInfo)                            {Q_UNUSED(pDllInfo)}
    virtual void onUnloadDllDebugEvent(DLL_INFO *pDllInfo)                          {Q_UNUSED(pDllInfo)}
    virtual void onOutputDebugStringEvent(DEBUG_EVENT *pDebugEvent)                 {Q_UNUSED(pDebugEvent)} // TODO Check
    virtual void onRipEvent(DEBUG_EVENT *pDebugEvent)                               {Q_UNUSED(pDebugEvent)}
    virtual void onProcessEntryPoint(ENTRYPOINT_INFO *pEntryPointInfo)              {Q_UNUSED(pEntryPointInfo)}
    virtual void onTargetEntryPoint(ENTRYPOINT_INFO *pEntryPointInfo);
    virtual void onBreakPoint(BREAKPOINT_INFO *pBreakPointInfo)                     {Q_UNUSED(pBreakPointInfo)}
    virtual void onFunctionEnter(FUNCTION_INFO *pFunctionInfo)                      {Q_UNUSED(pFunctionInfo)}
    virtual void onFunctionLeave(FUNCTION_INFO *pFunctionInfo)                      {Q_UNUSED(pFunctionInfo)}
    virtual void onSEH(SEH_INFO *pSEHInfo)                                          {Q_UNUSED(pSEHInfo)}
    virtual void onStep(STEP_INFO *pStepInfo);
    virtual void onException(EXCEPTION_INFO *pExceptionInfo)                        {Q_UNUSED(pExceptionInfo)}
    // TODO onException

    bool setBP(HANDLE hThread,qint64 nAddress,BP_TYPE bpType=BP_TYPE_CC,BP_INFO bpInfo=BP_INFO_UNKNOWN,qint32 nCount=-1,QVariant vInfo=QVariant());
    bool removeBP(HANDLE hThread,qint64 nAddress,XDebugger::BP_TYPE bpType);
    bool addAPIHook(HANDLE hThread, QString sFunctionName, BP_TYPE bpType=BP_TYPE_CC);
    bool removeAPIHook(QString sFunctionName);
    bool _addAPIHook(HANDLE hThread, DLL_INFO dllInfo, QString sFunctionName, BP_TYPE bpType);
    bool isAPIHook(QString sFunctionName);

    QString getFunctionNameByAddress(qint64 nAddress);

    enum REG_NAME
    {
        REG_NAME_EAX=0,
        REG_NAME_EBX,
        REG_NAME_ECX,
        REG_NAME_EDX,
        REG_NAME_ESI,
        REG_NAME_EDI,
        REG_NAME_EBP,
        REG_NAME_ESP,
        REG_NAME_EIP,
        REG_NAME_EFLAGS,
#ifdef Q_OS_WIN64
        REG_NAME_RAX,
        REG_NAME_RBX,
        REG_NAME_RCX,
        REG_NAME_RDX,
        REG_NAME_RSI,
        REG_NAME_RDI,
        REG_NAME_RBP,
        REG_NAME_RSP,
        REG_NAME_RIP,
        REG_NAME_RFLAGS,
        REG_NAME_R8,
        REG_NAME_R9,
        REG_NAME_R10,
        REG_NAME_R11,
        REG_NAME_R12,
        REG_NAME_R13,
        REG_NAME_R14,
        REG_NAME_R15,
#endif
    };

    quint64 getRegister(HANDLE hThread,REG_NAME regName);
    bool setRegister(HANDLE hThread,REG_NAME regName,quint64 nValue);
    TARGET_INFO *getTargetInfo();
    FILE_INFO *getFileInfo();
    qint64 _getRetAddress(HANDLE hThread);
    qint64 _getCurrentAddress(HANDLE hThread);
    void _messageString(MESSAGE_TYPE type,QString sText);

    QMap<REG_NAME,quint64> _getRegState(HANDLE hThread);

private:
    bool _setIP(HANDLE hThread,qint64 nAddress);
    bool _setStep(HANDLE hThread);

    enum LOAD_TYPE
    {
        LOAD_TYPE_EXE,
        LOAD_TYPE_DLL
    };

    enum HWBP_ACCESS
    {
        HWBP_ACCESS_EXECUTE=0,
        HWBP_ACCESS_READ,
        HWBP_ACCESS_READWRITE
    };

    enum HWBP_SIZE
    {
        HWBP_SIZE_BYTE=0,
        HWBP_SIZE_WORD,
        HWBP_SIZE_DWORD,
        HWBP_SIZE_QWORD
    };

    struct DBGREGS
    {
        quint64 regs[4];
        quint64 nControl;
        quint64 nStatus;
    };

    bool _loadFile(QString sFileName,LOAD_TYPE loadType,OPTIONS *pOptions=nullptr);
    void _getFileInfo(QString sFileName);
    void _handleBP(LOAD_TYPE loadType, BP_INFO bpInfo, qint64 nAddress, HANDLE hThread, BP_TYPE bpType, QVariant vInfo);
    qint32 _setHWBPX(HANDLE hThread,qint64 nAddress,HWBP_ACCESS access,HWBP_SIZE size);
    bool _removeHWBPX(HANDLE hThread,qint32 nIndex);
    bool _setDbgRegs(HANDLE hThread,DBGREGS *pDr);
    bool _getDbgRegs(HANDLE hThread,DBGREGS *pDr);

    bool _suspendOtherThreads(HANDLE hCurrentThread);
    bool _resumeOtherThreads(HANDLE hCurrentThread);

public slots:
    void process();
    void continueExecution();

signals:
    void messageString(quint32 nType,QString sText);
    void finished();
    void _onFileLoad(XBinary *pBinary);
    void _onTargetEntryPoint(XDebugger::ENTRYPOINT_INFO *pEntryPointInfo);
    void _onCreateThreadDebugEvent(XDebugger::CREATETHREAD_INFO *pCreateThreadInfo);
    void _onStep(XDebugger::STEP_INFO *pStepInfo);
    void _continueExecution();

private:
    QString d_sFileName;
    XDebugger::OPTIONS *d_pOptions;

    XDebugger::OPTIONS options;
    quint32 nProcessId;
    CREATEPROCESS_INFO createProcessInfo;
    FILE_INFO fileInfo;
    TARGET_INFO targetInfo;
    STATS stats;
    QMap<qint64,DLL_INFO> mapDLL;
    QMap<qint64,BREAKPOINT_INSTR> mapBP_Instr;
    QMap<qint64,BREAKPOINT_HW> mapBP_HW;
    QMap<quint32,HANDLE> mapThreads;
    QMap<QString,BP_TYPE> mapAPIHooks;
};

#endif // XDEBUGGER_H
