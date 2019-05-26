#ifndef XUNPACKER_H
#define XUNPACKER_H

#include <QObject>
#include "xdebugger.h"
#include "xwinapi.h"

class XUnpacker : public XDebugger
{
    Q_OBJECT
public:
    struct IMPORT_BUILD_RECORD
    {
        qint64 nPatchAddress;
        QString sLibrary;
        bool bIsOrdinal;
        quint64 nOrdinal;
        QString sFunction;
    };

    explicit XUnpacker(QObject *parent=nullptr);

protected:
    virtual void _clear();
    void addImportBuildRecord(IMPORT_BUILD_RECORD record);

private:
    QMap<qint64,IMPORT_BUILD_RECORD> mapImportBuildRecords;
};

#endif // XUNPACKER_H
