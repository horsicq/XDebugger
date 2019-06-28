#include "xunpacker.h"

XUnpacker::XUnpacker(QObject *parent) : XDebugger(parent)
{

}

bool XUnpacker::dumpToFile(QString sFileName, XUnpacker::DUMP_OPTIONS *pDumpOptions)
{
    bool bResult=false;

    qint64 nImageBase=getCreateProcessInfo()->nImageBase;
    qint64 nImageSize=getCreateProcessInfo()->nImageSize;

    const int N_BUFFER_SIZE=0x1000;

    char buffer[N_BUFFER_SIZE];

    QList<XProcess::MEMORY_REGION> listMR;
    XProcess::MEMORY_REGION mr={};

    int _bData=false;

    // The first block is a header
    for(qint64 nCurrentAddress=nImageBase+0x1000;nCurrentAddress<nImageBase+nImageSize;nCurrentAddress+=N_BUFFER_SIZE)
    {
        // TODO handle errors
        XProcess::MEMORY_FLAGS mf=XProcess::getMemoryFlags(getProcessHandle(),nCurrentAddress);

        bool bCreateNewSection=false;
        if(     (mf.bExecute!=mr.mf.bExecute)||
                (mf.bRead!=mr.mf.bRead)||
                (mf.bWrite!=mr.mf.bWrite))
        {
            bCreateNewSection=true;
        }

        if(nCurrentAddress+N_BUFFER_SIZE>=nImageBase+nImageSize)
        {
            bCreateNewSection=true;
        }

        bool bData=false;

        if(readData(nCurrentAddress,buffer,N_BUFFER_SIZE))
        {
            // TODO !!!
            if(XBinary::isEmptyData(buffer,N_BUFFER_SIZE))
            {
                bData=false;
                qDebug("Empty data: %x",nCurrentAddress);
            }
            else
            {
                bData=true;
                qDebug("Not empty data: %x",nCurrentAddress);
            }
        }

        if(!bCreateNewSection)
        {
            if((!_bData)&&(bData))
            {
                bCreateNewSection=true;
            }
        }

        _bData=bData;

        if(bData)
        {
            mr.nSize+=N_BUFFER_SIZE;
        }

        if(bCreateNewSection)
        {
            if(mr.nAddress)
            {
                listMR.append(mr);
            }
            mr.nAddress=nCurrentAddress;
            mr.nSize=0;
            mr.mf=mf;
        }
    }

    // Fix
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSH;

    int nCountMR=listMR.count();

    for(int i=0;i<nCountMR;i++)
    {
        XPE_DEF::IMAGE_SECTION_HEADER record={};

        record.VirtualAddress=listMR.at(i).nAddress-nImageBase;

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

    XPE::HEADER_OPTIONS headerOptions={};
    headerOptions.nMachine=getCreateProcessInfo()->headerInfo.nMachine;
    headerOptions.nCharacteristics=getCreateProcessInfo()->headerInfo.nCharacteristics;
    headerOptions.nMagic=getCreateProcessInfo()->headerInfo.nMagic;
    headerOptions.nImagebase=getCreateProcessInfo()->headerInfo.nImageBase;
    headerOptions.nResourceRVA=getCreateProcessInfo()->headerInfo.nResourceRVA;
    headerOptions.nResourceSize=getCreateProcessInfo()->headerInfo.nResourceSize;
    headerOptions.nFileAlignment=0x200;
    headerOptions.nSectionAlignment=0x1000;
    headerOptions.nAddressOfEntryPoint=pDumpOptions->nAddressOfEntryPoint;

    QByteArray baHeader=XPE::createHeaderStub(&headerOptions);

    QFile file;
    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadWrite))
    {
        file.write(baHeader.data(),baHeader.size());

        XPE pe(&file);

        for(int i=0;i<nCountMR;i++)
        {
            QByteArray baSection=read_array(listMR.at(i).nAddress,listMR.at(i).nSize);

            XPE_DEF::IMAGE_SECTION_HEADER ish=listSH.at(i);

            pe.addSection(&ish,baSection.data(),baSection.size());
        }

        QMap<qint64, QString> mapImport=getImportMap();

        pe.addImportSection(&mapImport);

        if(getCreateProcessInfo()->nImageBase!=getCreateProcessInfo()->headerInfo.nImageBase)
        {
            // TODO
            qDebug("Relocs Present");
        }

        bResult=true;

        file.close();
    }

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

void XUnpacker::_clear()
{
    XDebugger::_clear();

    mapImportBuildRecords.clear();
}

void XUnpacker::addImportBuildRecord(XUnpacker::IMPORT_BUILD_RECORD record)
{
    mapImportBuildRecords.insert(record.nPatchAddress,record);
}
