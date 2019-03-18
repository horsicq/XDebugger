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

!contains(XCONFIG, Formats) {
    XCONFIG += Formats
    include(../Formats/qpe.pri)
}
