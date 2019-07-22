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
        bool bLastSection=false;

        if(     (mf.bExecute!=mr.mf.bExecute)||
                (mf.bRead!=mr.mf.bRead)||
                (mf.bWrite!=mr.mf.bWrite))
        {
            bCreateNewSection=true;
        }

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
                qDebug("Empty data: %x",nCurrentAddress-nImageBase);
            }
            else
            {
                bData=true;
                qDebug("Not empty data: %x",nCurrentAddress-nImageBase);
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

        if((bData)&&(!bCreateNewSection))
        {
            mr.nSize+=N_BUFFER_SIZE;
            qDebug("Added");
        }

        if(bCreateNewSection||bLastSection)
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

//    XProcessDevice xpd(this);

//    if(xpd.openHandle(getProcessHandle(),getCreateProcessInfo()->nImageBase,getCreateProcessInfo()->nImageSize,QIODevice::ReadOnly))
//    {
//        XPE pe(&xpd,true,getCreateProcessInfo()->nImageBase);

//        if(pe.isValid())
//        {
//            headerOptions.nMachine=pe.getFileHeader_Machine();
//            headerOptions.nCharacteristics=pe.getFileHeader_Characteristics();
//            headerOptions.nMagic=pe.getOptionalHeader_Magic();
//            headerOptions.nImagebase=pe.getOptionalHeader_ImageBase();
//            headerOptions.nDllcharacteristics=pe.getOptionalHeader_DllCharacteristics();
//            headerOptions.nMajorOperationSystemVersion=pe.getOptionalHeader_MajorOperatingSystemVersion();
//            headerOptions.nMinorOperationSystemVersion=pe.getOptionalHeader_MinorOperatingSystemVersion();
//            headerOptions.nSubsystem=pe.getOptionalHeader_Subsystem();
//            headerOptions.nResourceRVA=pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress;
//            headerOptions.nResourceSize=pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE).Size;
//        }

//        xpd.close();
//    }

    headerOptions.nMachine=getCreateProcessInfo()->headerInfo.nMachine;
    headerOptions.nCharacteristics=getCreateProcessInfo()->headerInfo.nCharacteristics;
    headerOptions.nMagic=getCreateProcessInfo()->headerInfo.nMagic;
    headerOptions.nImagebase=getCreateProcessInfo()->headerInfo.nImageBase;
    headerOptions.nDllcharacteristics=getCreateProcessInfo()->headerInfo.nDllcharacteristics;
    headerOptions.nMajorOperationSystemVersion=getCreateProcessInfo()->headerInfo.nMajorOperationSystemVersion;
    headerOptions.nMinorOperationSystemVersion=getCreateProcessInfo()->headerInfo.nMinorOperationSystemVersion;
    headerOptions.nSubsystem=getCreateProcessInfo()->headerInfo.nSubsystem;
    headerOptions.nResourceRVA=getCreateProcessInfo()->headerInfo.nResourceRVA;
    headerOptions.nResourceSize=getCreateProcessInfo()->headerInfo.nResourceSize;

//    dumpMemoryRegionToFile("C:\\tmp_build\\header.dmp",getCreateProcessInfo()->nImageBase,0x1000);

    headerOptions.nFileAlignment=0x200;
    headerOptions.nSectionAlignment=0x1000;
    headerOptions.nAddressOfEntryPoint=pDumpOptions->nAddressOfEntryPoint;

//    QByteArray baHeader=XPE::createHeaderStub(&headerOptions);

    QByteArray baHeader=read_array(getCreateProcessInfo()->nImageBase,0x400);

    QBuffer buBuffer;
    buBuffer.setBuffer(&baHeader);

    if(buBuffer.open(QIODevice::ReadWrite))
    {
        XPE pe(&buBuffer);

        pe.setOptionalHeader_AddressOfEntryPoint(pDumpOptions->nAddressOfEntryPoint);
        pe.setFileHeader_NumberOfSections(0);

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

void XUnpacker::setResultFileName(QString sResultFileName)
{
    this->sResultFileName=sResultFileName;
}

QString XUnpacker::getResultFileName()
{
    return sResultFileName;
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
