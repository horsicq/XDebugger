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

    static KERNEL32_GETPROCADDRESS handle_Kernel32_getProcAddress(XDebugger *pDebugger,XDebugger::FUNCTION_INFO *pFunctionInfo);
};

#endif // XWINAPI_H
