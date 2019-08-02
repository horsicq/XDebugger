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
    };

    enum MESSAGE_TYPE
    {
        MESSAGE_TYPE_UNKNOWN=0,
        MESSAGE_TYPE_INFO,
        MESSAGE_TYPE_WARNING,
        MESSAGE_TYPE_ERROR
    };

    explicit XDebugger(QObject *parent=nullptr);
    bool loadFile(QString sFileName,OPTIONS *pOptions=nullptr);

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
    HANDLE getProcessHandle();
    QMap<qint64,DLL_INFO> *getMapDLL();
    quint64 getFunctionResult(FUNCTION_INFO *pFunctionInfo);
    quint64 getFunctionParameter(FUNCTION_INFO *pFunctionInfo,qint32 nNumber); // TODO call conversions
    bool readData(qint64 nAddress,char *pBuffer,qint32 nBufferSize);
    bool writeData(qint64 nAddress,char *pBuffer,qint32 nBufferSize);
    QByteArray read_array(qint64 nAddress,qint32 nSize);
    QString read_ansiString(qint64 nAddress,qint64 nMaxSize=256);
    QString read_unicodeString(qint64 nAddress,qint64 nMaxSize=256);
    quint32 read_uint32(qint64 nAddress);
    quint64 read_uint64(qint64 nAddress);

    qint64 findSignature(qint64 nAddress, qint64 nSize, QString sSignature);
    void skipFunction(HANDLE hThread, quint32 nNumberOfParameters,quint64 nResult);
    void stepInto(HANDLE hThread,QVariant vInfo=QVariant());

    void stop();

    bool dumpMemoryRegionToFile(QString sFilename,qint64 nAddress,qint64 nSize);
    bool isAddressInImage(qint64 nAddress);

private:
    bool _setIP(HANDLE hThread,qint64 nAddress);
    bool _setStep(HANDLE hThread);


protected:
    struct RAW_HEADER_INFO
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
    };

    struct CREATEPROCESS_INFO
    {
        HANDLE hProcess;
        HANDLE hThread;
        QString sFileName;
        qint64 nImageBase;
        qint64 nImageSize;
        qint64 nStartAddress;
        qint64 nThreadLocalBase;

        RAW_HEADER_INFO headerInfo;
    };
    struct STATS
    {
        bool bStepInto;
        QVariant vStepIntoInfo;
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
        BP_TYPE_CC
    };
    enum BP_INFO
    {
        BP_INFO_UNKNOWN=0,
        BP_INFO_ENTRYPOINT,
        BP_INFO_API_ENTER,
        BP_INFO_API_LEAVE,
        BP_INFO_USER
    };
    struct BREAKPOINT
    {
        qint64 nAddress;
        HANDLE hThread;
        qint32 nCount;
        BP_TYPE bpType;
        BP_INFO bpInfo;
        char origData[4];
        qint32 nOrigDataSize;
        QVariant vInfo;
    };
    struct STEP
    {
        qint64 nAddress;
        HANDLE hThread;
        QVariant vInfo;
    };

    virtual void _clear();

    virtual void onCreateProcessDebugEvent(CREATEPROCESS_INFO *pCreateProcessInfo) {}
    virtual void onCreateThreadDebugEvent(CREATETHREAD_INFO *pCreateThreadInfo) {}
    virtual void onExitProcessDebugEvent(EXITPROCESS_INFO *pExitProcessInfo) {}
    virtual void onExitThreadDebugEvent(EXITTHREAD_INFO *pExitThreadInfo) {}
    virtual void onLoadDllDebugEvent(DLL_INFO *pDllInfo) {}
    virtual void onUnloadDllDebugEvent(DLL_INFO *pDllInfo) {}
    virtual void onOutputDebugStringEvent(DEBUG_EVENT *pDebugEvent) {}
    virtual void onRipEvent(DEBUG_EVENT *pDebugEvent) {}
    virtual void onEntryPoint(ENTRYPOINT_INFO *pEntryPointInfo) {}
    virtual void onBreakPoint(BREAKPOINT *pBp) {}
    virtual void onFunctionEnter(FUNCTION_INFO *pFunctionInfo) {}
    virtual void onFunctionLeave(FUNCTION_INFO *pFunctionInfo) {}
    virtual void onStep(STEP *pStep) {}
    // TODO onException

    bool setBP(qint64 nAddress,BP_TYPE bpType=BP_TYPE_CC,BP_INFO bpInfo=BP_INFO_UNKNOWN,qint32 nCount=-1,QVariant vInfo=QVariant());
    bool removeBP(qint64 nAddress);
    bool addAPIHook(QString sFunctionName);
    bool removeAPIHook(QString sFunctionName);
    bool _addAPIHook(DLL_INFO dllInfo,QString sFunctionName);

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
        REG_NAME_EIP
    };

    quint64 getRegister(HANDLE hThread,REG_NAME regName);
    bool setRegister(HANDLE hThread,REG_NAME regName,quint64 nValue);
    CREATEPROCESS_INFO *getCreateProcessInfo();

    qint64 _getRetAddress(HANDLE hThread);

    void _messageString(MESSAGE_TYPE type,QString sText);

signals:
    void messageString(quint32 nType,QString sText);

private:
    XDebugger::OPTIONS options;
    quint32 nProcessId;
    CREATEPROCESS_INFO createProcessInfo;
    STATS stats;
    QMap<qint64,DLL_INFO> mapDLL;
    QMap<qint64,BREAKPOINT> mapBP;
    QMap<quint32,HANDLE> mapThreads;
    QSet<QString> stAPIHooks;
};

#endif // XDEBUGGER_H
