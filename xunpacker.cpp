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

    // The first block is a header
    for(qint64 nCurrentAddress=nImageBase+0x1000;nCurrentAddress<nImageBase+nImageSize;nCurrentAddress+=N_BUFFER_SIZE)
    {
        // TODO handle errors
        XProcess::MEMORY_FLAGS mf=XProcess::getMemoryFlags(getProcessHandle(),nCurrentAddress);
        if(readData(nCurrentAddress,buffer,N_BUFFER_SIZE))
        {
            // TODO !!!
            if(XBinary::isEmptyData(buffer,N_BUFFER_SIZE))
            {
                qDebug("Empty data: %x",nCurrentAddress);
            }
            else
            {
                qDebug("Not empty data: %x",nCurrentAddress);
            }
        }
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
