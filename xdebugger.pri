INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xdebugger.h

SOURCES += \
    $$PWD/xdebugger.cpp

!contains(XCONFIG, xprocess) {
    XCONFIG += xprocess
    include(../XProcess/xprocess.pri)
}

!contains(XCONFIG, xpe) {
    XCONFIG += xpe
    include(../Formats/xpe.pri)
}
