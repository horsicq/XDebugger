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

    struct RELOC_BUILD_RECORD
    {
        qint64 nPatchAddress;
        quint64 nValue;
    };

    struct DUMP_OPTIONS
    {
        qint64 nAddressOfEntryPoint;
        bool bFixChecksum;
        bool bPatchNWError6002;
    };

    enum UNPACK_OPTIONS_ID
    {
        UNPACK_OPTIONS_ID_UNKNOWN=0,
        UNPACK_OPTIONS_ID_FIXCHECKSUM,
        UNPACK_OPTIONS_ID_PATCHNW
    };

    enum UNPACK_OPTIONS_VAR_TYPE
    {
        UNPACK_OPTIONS_VAR_TYPE_UNKNOWN=-1,
        UNPACK_OPTIONS_VAR_TYPE_BOOL
    };

    struct UNPACK_OPTIONS_RECORD
    {
        quint32 nID;
        QString sName;
        UNPACK_OPTIONS_VAR_TYPE varType;
        QVariant var;
    };

    explicit XUnpacker(QObject *parent=nullptr);

    bool dumpToFile(QString sFileName,DUMP_OPTIONS *pDumpOptions);
    QMap<qint64,QString> getImportMap();
    QList<qint64> getRelocsList();

    QString getResultFileName();

    bool unpack(QString sFileName,QString sResultFileName,QList<UNPACK_OPTIONS_RECORD> *pListUnpackOptions);

    virtual QList<UNPACK_OPTIONS_RECORD> getDefaultUnpackOptions();
    QVariant getUnpackOptionValue(quint32 nID);

protected:
    virtual void _clear();
    void addImportBuildRecord(IMPORT_BUILD_RECORD record);
    void addRelocBuildRecord(RELOC_BUILD_RECORD record);

private:
    QMap<qint64,IMPORT_BUILD_RECORD> mapImportBuildRecords;
    QMap<qint64,RELOC_BUILD_RECORD> mapRelocBuildRecords;

    QString sResultFileName;
    QList<UNPACK_OPTIONS_RECORD> listUnpackOptions;
};

#endif // XUNPACKER_H
