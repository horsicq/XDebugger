INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xdebugger.h \
    $$PWD/xwinapi.h \
    $$PWD/xunpacker.h

SOURCES += \
    $$PWD/xdebugger.cpp \
    $$PWD/xwinapi.cpp \
    $$PWD/xunpacker.cpp

!contains(XCONFIG, xprocess) {
    XCONFIG += xprocess
    include($$PWD/../XProcess/xprocess.pri)
}

!contains(XCONFIG, xpe) {
    XCONFIG += xpe
    include($$PWD/../Formats/xpe.pri)
}
