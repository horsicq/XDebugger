#ifndef XUNPACKER_H
#define XUNPACKER_H

#include <QObject>
#include <QBuffer>
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

    struct DUMP_OPTIONS
    {
        qint64 nAddressOfEntryPoint;
    };

    explicit XUnpacker(QObject *parent=nullptr);

    bool dumpToFile(QString sFileName,DUMP_OPTIONS *pDumpOptions);
    QMap<qint64,QString> getImportMap();

    void setResultFileName(QString sResultFileName);
    QString getResultFileName();

protected:
    virtual void _clear();
    void addImportBuildRecord(IMPORT_BUILD_RECORD record);

private:
    QMap<qint64,IMPORT_BUILD_RECORD> mapImportBuildRecords;

    QString sResultFileName;
};

#endif // XUNPACKER_H
