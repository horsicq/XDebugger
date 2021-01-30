// copyright (c) 2019-2021 hors<horsicq@gmail.com>
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
        quint64 nValue;
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
        QString sDescription;
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
