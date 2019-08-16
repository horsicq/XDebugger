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
};

#endif // XWINAPI_H
