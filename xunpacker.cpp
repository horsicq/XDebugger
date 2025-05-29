// copyright (c) 2019-2025 hors<horsicq@gmail.com>
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
#include "xunpacker.h"

XUnpacker::XUnpacker(QObject *parent) : XDebugger(parent)
{

}

bool XUnpacker::dumpToFile(QString sFileName, XUnpacker::DUMP_OPTIONS *pDumpOptions)
{
    bool bResult=false;

    qint64 nImageBase=getTargetInfo()->nImageBase;
    qint64 nImageSize=getTargetInfo()->nImageSize;

    if(pDumpOptions->bPatchNWError6002)
    {
        if(!(getFileInfo()->bIs64))
        {
            //   004947D5  |.  8B40 24                      MOV EAX,DWORD PTR DS:[EAX+24]
            //   004947D8  |.  C1E8 1F                      SHR EAX,1F
            //   004947DB  |.  F7D0                         NOT EAX
            //   004947DD  |.  83E0 01                      AND EAX,00000001
            qint64 nNWAddress=findSignature(nImageBase,nImageSize,"8B4024C1E81FF7D083E001");

            if(nNWAddress!=-1)
            {
                 _messageString(MESSAGE_TYPE_WARNING,tr("NW Address found: 0x%1").arg(nNWAddress,0,16));

                // 83 c8
                // AND ->OR
                write_uint8(nNWAddress+9,0xC8);
            }
        }
    }

    const int N_BUFFER_SIZE=0x1000;

    char buffer[N_BUFFER_SIZE];

    QList<XProcess::MEMORY_REGION> listMR;
    XProcess::MEMORY_REGION mr={};

    int _bData=false;

    // The first block is a header
    // TODO directories!!!

    qint64 nResourcesStart=S_ALIGN_DOWN(getFileInfo()->nResourceRVA,0x1000)+nImageBase;
    qint64 nResourcesEnd=S_ALIGN_UP(getFileInfo()->nResourceRVA+getFileInfo()->nResourceSize,0x1000)+nImageBase;

    for(qint64 nCurrentAddress=nImageBase+0x1000;nCurrentAddress<nImageBase+nImageSize;nCurrentAddress+=N_BUFFER_SIZE)
    {
        // TODO handle errors
        XProcess::MEMORY_FLAGS mf=XProcess::getMemoryFlags(getProcessHandle(),nCurrentAddress);

//        qint64 nTemp=nCurrentAddress-nImageBase;

        bool bCreateNewSection=false;
        bool bLastSection=false;

        if(     (mf.bExecute!=mr.mf.bExecute)||
                (mf.bRead!=mr.mf.bRead)||
                (mf.bWrite!=mr.mf.bWrite))
        {
            bCreateNewSection=true;
        }

        if( (nCurrentAddress==nResourcesStart)||
            (nCurrentAddress==nResourcesEnd))
        {
            bCreateNewSection=true;
        }

        bool bResources=(nCurrentAddress>=nResourcesStart)&&(nCurrentAddress<nResourcesEnd);

        if(nCurrentAddress+N_BUFFER_SIZE>=nImageBase+nImageSize)
        {
            bLastSection=true;
        }

        bool bData=false;

        if(readData(nCurrentAddress,buffer,N_BUFFER_SIZE))
        {
            // TODO !!!
            if(XBinary::isEmptyData(buffer,N_BUFFER_SIZE))
            {
                bData=false;
                QString sDebugString=QString("%1: %2").arg(tr("Empty data")).arg(nCurrentAddress-nImageBase,0,16);
                _messageString(MESSAGE_TYPE_INFO,sDebugString);
            }
            else
            {
                bData=true;
                QString sDebugString=QString("%1: %2").arg(tr("Not empty data")).arg(nCurrentAddress-nImageBase,0,16);
                _messageString(MESSAGE_TYPE_INFO,sDebugString);
            }
        }

        if(!bCreateNewSection)
        {
            if((!_bData)&&(bData))
            {
                if(!bResources)
                {
                    bCreateNewSection=true;
                }
            }
        }

        _bData=bData;

        if(((bData)&&(!bCreateNewSection))||(bResources))
        {
            mr.nSize+=N_BUFFER_SIZE;
        }

        if(bCreateNewSection)
        {
            if(mr.nAddress)
            {
                listMR.append(mr);
            }
            if(bCreateNewSection)
            {
                mr.nAddress=nCurrentAddress;
                mr.nSize=0x1000;
                mr.mf=mf;
            }
        }

        if(bLastSection)
        {
            if(mr.nAddress)
            {
                listMR.append(mr);
            }
        }
    }

    // Fix
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSH;

    int nCountMR=listMR.count();

    for(int i=0;i<nCountMR;i++)
    {
        XPE_DEF::IMAGE_SECTION_HEADER record={};

        record.VirtualAddress=listMR.at(i).nAddress-nImageBase;

        if(listMR.at(i).nAddress==nResourcesStart)
        {
            strcpy((char *)record.Name,".rsrc");
        }

        if(i==(nCountMR-1))
        {
            record.Misc.VirtualSize=nImageSize-record.VirtualAddress;
        }
        else
        {
            record.Misc.VirtualSize=(listMR.at(i+1).nAddress-nImageBase)-record.VirtualAddress;
        }

        record.PointerToRawData=0; // Auto
        record.SizeOfRawData=listMR.at(i).nSize;

        record.Characteristics=0x20000000|0x40000000|0x00000020|0x00000040;

        if(listMR.at(i).mf.bWrite)
        {
            record.Characteristics|=0x80000000;
        }

        listSH.append(record);
    }

    XBinary::removeFile(sFileName);

    qint64 nDelta=getTargetInfo()->nImageBase-getFileInfo()->nImageBase;

    QMapIterator<qint64, RELOC_BUILD_RECORD> i(mapRelocBuildRecords);
    while(i.hasNext())
    {
        i.next();

        RELOC_BUILD_RECORD record=i.value();

#ifndef Q_OS_WIN64
        quint32 nValue=read_uint32(record.nPatchAddress);
        nValue-=nDelta;
        write_uint32(record.nPatchAddress,nValue);
#else
        quint64 nValue=read_uint64(record.nPatchAddress);
        nValue-=nDelta;
        write_uint64(record.nPatchAddress,nValue);
#endif
    }

    QByteArray baHeader=read_array(getTargetInfo()->nImageBase,0x200);

    QBuffer buBuffer;
    buBuffer.setBuffer(&baHeader);

//    QFile file;
//    file.setFileName(sFileName);

//    if(file.open(QIODevice::ReadWrite))
//    {
//        file.write(baHeader.data(),baHeader.size());

//        XPE pe(&file);

    if(buBuffer.open(QIODevice::ReadWrite))
    {
        XPE pe(&buBuffer);

        pe.setOptionalHeader_AddressOfEntryPoint(pDumpOptions->nAddressOfEntryPoint);

        pe.setFileHeader_NumberOfSections(0);
        pe.setOptionalHeader_FileAlignment(0x200);
        pe.setOptionalHeader_SectionAlignment(0x1000);
        pe.setOptionalHeader_SizeOfHeaders(0x200);

        for(int i=0;i<nCountMR;i++)
        {
            XPE_DEF::IMAGE_SECTION_HEADER ish=listSH.at(i);

            QByteArray baSection=read_array(listMR.at(i).nAddress,listMR.at(i).nSize);

            qint64 _nSize=XBinary::getPhysSize(baSection.data(),baSection.size());

            ish.SizeOfRawData=S_ALIGN_UP(_nSize,0x200);
            baSection.resize(ish.SizeOfRawData);

            pe.addSection(&ish,baSection.data(),baSection.size());
        }
        // Fix relocs
        if(nDelta)
        {
            pe.setOptionalHeader_ImageBase(pe.getOptionalHeader_ImageBase()-nDelta);
        }

        QMap<qint64, QString> mapImport=getImportMap();

        if(mapImport.size())
        {
            pe.addImportSection(&mapImport);
        }

        if(getTargetInfo()->nImageBase!=(qint64)getFileInfo()->nImageBase)
        {
            _messageString(MESSAGE_TYPE_INFO,tr("Relocs present"));
        }

        QList<qint64> listRelocs=getRelocsList();

        if(listRelocs.size())
        {
            pe.addRelocsSection(&listRelocs);
        }

        if(pDumpOptions->bFixChecksum)
        {
            pe.fixCheckSum();
        }
        else
        {
            pe.setOptionalHeader_CheckSum(0);
        }

        // TODO virtual function

        bResult=true;

//        file.close();
        buBuffer.close();
    }

    if(bResult)
    {
        QFile file;
        file.setFileName(sFileName);

        if(file.open(QIODevice::ReadWrite))
        {
            file.write(baHeader.data(),baHeader.size());

            file.close();
        }
        else
        {
            bResult=false;
        }
    }

//    QFile file;
//    file.setFileName(sFileName);

//    if(file.open(QIODevice::ReadWrite))
//    {
//        file.write(baHeader.data(),baHeader.size());

//        XPE pe(&file);

//        pe.setOptionalHeader_AddressOfEntryPoint(pDumpOptions->nAddressOfEntryPoint);
//        pe.setFileHeader_NumberOfSections(0);

//        for(int i=0;i<nCountMR;i++)
//        {
//            QByteArray baSection=read_array(listMR.at(i).nAddress,listMR.at(i).nSize);

//            XPE_DEF::IMAGE_SECTION_HEADER ish=listSH.at(i);

//            pe.addSection(&ish,baSection.data(),baSection.size());
//        }

//        QMap<qint64, QString> mapImport=getImportMap();

//        pe.addImportSection(&mapImport);

//        if(getCreateProcessInfo()->nImageBase!=getCreateProcessInfo()->headerInfo.nImageBase)
//        {
//            // TODO
//            qDebug("Relocs Present");
//        }

//        bResult=true;

//        file.close();
//    }

    return bResult;
}

QMap<qint64, QString> XUnpacker::getImportMap()
{
    QMap<qint64, QString> mapResult;

    QMapIterator<qint64, IMPORT_BUILD_RECORD> i(mapImportBuildRecords);
    while(i.hasNext())
    {
        i.next();

        IMPORT_BUILD_RECORD record=i.value();

        QString sFunction;

        if(record.bIsOrdinal)
        {
            sFunction=QString::number(record.nOrdinal);
        }
        else
        {
            sFunction=record.sFunction;
        }

        mapResult.insert(record.nPatchAddress,record.sLibrary+"#"+sFunction);
    }

    return mapResult;
}

QList<qint64> XUnpacker::getRelocsList()
{
    QList<qint64> listResult;

    QMapIterator<qint64, RELOC_BUILD_RECORD> i(mapRelocBuildRecords);
    while(i.hasNext())
    {
        i.next();

        RELOC_BUILD_RECORD record=i.value();

        record.nPatchAddress-=getTargetInfo()->nImageBase;

        listResult.append(record.nPatchAddress);
    }

    return listResult;
}

QString XUnpacker::getResultFileName()
{
    return sResultFileName;
}

bool XUnpacker::unpack(QString sFileName, QString sResultFileName, QList<UNPACK_OPTIONS_RECORD> *pListUnpackOptions)
{
    this->sResultFileName=sResultFileName;
    listUnpackOptions=*pListUnpackOptions;

    XDebugger::OPTIONS options={};
    options.bShowWindow=true;

    return loadFile(sFileName,&options);
}

QList<XUnpacker::UNPACK_OPTIONS_RECORD> XUnpacker::getDefaultUnpackOptions()
{
    QList<XUnpacker::UNPACK_OPTIONS_RECORD> listResult;

    {
        UNPACK_OPTIONS_RECORD record={};

        record.nID=UNPACK_OPTIONS_ID_FIXCHECKSUM;
        record.sName="fixchecksum";
        record.sDescription=tr("Fix checksum");
        record.varType=UNPACK_OPTIONS_VAR_TYPE_BOOL;
        record.var=true;

        listResult.append(record);
    }
    {
        UNPACK_OPTIONS_RECORD record={};

        record.nID=UNPACK_OPTIONS_ID_PATCHNW;
        record.sName="patchnw";
        record.sDescription=tr("Patch NW Address(fix Error 6002)");
        record.varType=UNPACK_OPTIONS_VAR_TYPE_BOOL;
        record.var=true;

        listResult.append(record);
    }

    return listResult;
}

QVariant XUnpacker::getUnpackOptionValue(quint32 nID)
{
    QVariant varResult=0;

    int nCount=listUnpackOptions.count();

    for(int i=0;i<nCount;i++)
    {
        if(listUnpackOptions.at(i).nID==nID)
        {
            varResult=listUnpackOptions.at(i).var;
            break;
        }
    }

    return varResult;
}

void XUnpacker::_clear()
{
    XDebugger::_clear();

    mapImportBuildRecords.clear();
    mapRelocBuildRecords.clear();
}

void XUnpacker::addImportBuildRecord(XUnpacker::IMPORT_BUILD_RECORD record)
{
    QString sDebugString=QString("Import [%1] <- %2 : %3 : %4").arg(record.nPatchAddress,0,16).arg(record.nValue,0,16).arg(record.sLibrary).arg(record.sFunction);
    _messageString(MESSAGE_TYPE_INFO,sDebugString);

    mapImportBuildRecords.insert(record.nPatchAddress,record);
}

void XUnpacker::addRelocBuildRecord(XUnpacker::RELOC_BUILD_RECORD record)
{
    QString sDebugString=QString("Reloc [%1] <- %2").arg(record.nPatchAddress,0,16).arg(record.nValue,0,16);
    _messageString(MESSAGE_TYPE_INFO,sDebugString);

    mapRelocBuildRecords.insert(record.nPatchAddress,record);
}
