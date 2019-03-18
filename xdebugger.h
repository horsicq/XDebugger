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
#include "qpe.h"

class XDebugger : public QObject
{
    Q_OBJECT
public:
    struct OPTIONS
    {
        bool bShowWindow;
    };

    explicit XDebugger(QObject *parent = nullptr);
    bool loadFile(QString sFileName,OPTIONS *pOptions);

private:
    enum BP_TYPE
    {
        BP_TYPE_UNKNOWN=0,
        BP_TYPE_CC
    };

    enum BP_INFO
    {
        BP_INFO_UNKNOWN=0,
        BP_INFO_ENTRYPOINT
    };

    struct BREAKPOINT
    {
        qint32 nCount;
        BP_TYPE bpType;
        BP_INFO bpInfo;
    };

    void clear();

protected:
    struct DLL_INFO
    {
        QString sName;
        QString sFileName;
        qint64 nImageBase;
        qint64 nImageSize;
    };

    virtual void onCreateProcessDebugEvent(DEBUG_EVENT *pDebugEvent){};
    virtual void onCreateThreadDebugEvent(DEBUG_EVENT *pDebugEvent){};
    virtual void onExitProcessDebugEvent(DEBUG_EVENT *pDebugEvent){};
    virtual void onExitThreadDebugEvent(DEBUG_EVENT *pDebugEvent){};
    virtual void onLoadDllDebugEvent(DLL_INFO *pDllInfo){};
    virtual void onUnloadDllDebugEvent(DLL_INFO *pDllInfo){};
    virtual void onOutputDebugStringEvent(DEBUG_EVENT *pDebugEvent){};
    virtual void onRipEvent(DEBUG_EVENT *pDebugEvent){};

    HANDLE getProcessHandle();
    bool addBP(qint64 nAddress,BREAKPOINT *pBP);
    bool removeBP(qint64 nAddress);
signals:

public slots:

private:
    PROCESS_INFORMATION processInfo;
    STARTUPINFOW sturtupInfo;
    CREATE_PROCESS_DEBUG_INFO createProcessDebugInfo;
    QMap<qint64,DLL_INFO> mapDLL;
    QMap<qint64,BREAKPOINT> mapBP;
};

#endif // XDEBUGGER_H
