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

    XBinary::removeFile(sFileName);

    XPE::HEADER_OPTIONS headerOptions={};
    headerOptions.nFileAlignment=0x200;
    headerOptions.nSectionAlignment=0x1000;

    QByteArray baHeader=XPE::createHeaderStub(&headerOptions);

    QFile file;
    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadWrite))
    {
        file.write(baHeader.data(),baHeader.size());

        XPE pe(&file);

        XPE_DEF::IMAGE_SECTION_HEADER ish={};
        pe.addSection(&ish,"123",3);

        file.close();
    }

    return bResult;
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
