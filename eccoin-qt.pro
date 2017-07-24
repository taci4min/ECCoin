TEMPLATE = app
TARGET = eccoin-windows-daemon
VERSION = 0.7.2
INCLUDEPATH += src src/json src/qt
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE
CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static
CONFIG += widgets
CONFIG += c++11
QT += core gui network widgets

QMAKE_CXXFLAGS = -fpermissive

greaterThan(QT_MAJOR_VERSION, 4) {
    QT += widgets
    DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0
}

# UNCOMMENT THIS SECTION TO BUILD ON WINDOWS
# Change paths if needed, these use the foocoin/deps.git repository locations

win32{
    BOOST_LIB_SUFFIX=-mgw49-mt-s-1_57
    BOOST_INCLUDE_PATH=C:/deps/boost_1_57_0
    BOOST_LIB_PATH=C:/deps/boost_1_57_0/stage/lib
    BDB_INCLUDE_PATH=C:/deps/db-4.8.30.NC/build_unix
    BDB_LIB_PATH=C:/deps/db-4.8.30.NC/build_unix
    OPENSSL_INCLUDE_PATH=C:/deps/openssl-1.0.1l/include
    OPENSSL_LIB_PATH=C:/deps/openssl-1.0.1l
    MINIUPNPC_INCLUDE_PATH=C:/deps/
    MINIUPNPC_LIB_PATH=C:/deps/miniupnpc/
    QRENCODE_INCLUDE_PATH=C:/deps/qrencode-3.4.4
    QRENCODE_LIB_PATH=C:/deps/qrencode-3.4.4/.libs
}


# for boost 1.37, add -mt to the boost libraries
# use: qmake BOOST_LIB_SUFFIX=-mt
# for boost thread win32 with _win32 sufix
# use: BOOST_THREAD_LIB_SUFFIX=_win32-...
# or when linking against a specific BerkelyDB version: BDB_LIB_SUFFIX=-4.8

# Dependency library locations can be customized with:
#    BOOST_INCLUDE_PATH, BOOST_LIB_PATH, BDB_INCLUDE_PATH,
#    BDB_LIB_PATH, OPENSSL_INCLUDE_PATH and OPENSSL_LIB_PATH respectively

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

# use: qmake "RELEASE=1"
contains(RELEASE, 1) {
    # Mac: compile for maximum compatibility (10.5, 32-bit)
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.5 -arch x86_64 -isysroot /Developer/SDKs/MacOSX10.5.sdk

    !windows:!macx {
        # Linux: static link
        LIBS += -Wl,-Bstatic
    }
}

!win32 {
# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
QMAKE_LFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
# We need to exclude this for Windows cross compile with MinGW 4.2.x, as it will result in a non-working executable!
# This can be enabled for Windows, when we switch to MinGW >= 4.4.x.
}
# for extra security on Windows: enable ASLR and DEP via GCC linker flags
win32:QMAKE_LFLAGS *= -static
win32:QMAKE_LFLAGS += -static-libgcc -static-libstdc++
lessThan(QT_MAJOR_VERSION, 5): win32: QMAKE_LFLAGS *= -static

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    LIBS += -lqrencode
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support

USE_UPNP=1
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += DMINIUPNP_STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    win32:LIBS += -liphlpapi
}


# use: qmake "USE_DBUS=1"
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}

# use: qmake "USE_IPV6=1" ( enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(BITCOIN_NEED_QT_PLUGINS, 1) {
    DEFINES += BITCOIN_NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

INCLUDEPATH += src/leveldb/include src/leveldb/helpers
LIBS += $$PWD/src/leveldb/libleveldb.a $$PWD/src/leveldb/libmemenv.a

!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a
} else {
    # make an educated guess about what the ranlib command is called
    isEmpty(QMAKE_RANLIB) {
        QMAKE_RANLIB = $$replace(QMAKE_STRIP, strip, ranlib)
    }
    LIBS += -lshlwapi
    #genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX TARGET_OS=OS_WINDOWS_CROSSCOMPILE $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libleveldb.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libmemenv.a
}
genleveldb.target = $$PWD/src/leveldb/libleveldb.a
genleveldb.depends = FORCE
PRE_TARGETDEPS += $$PWD/src/leveldb/libleveldb.a
QMAKE_EXTRA_TARGETS += genleveldb
# Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
#QMAKE_CLEAN += $$PWD/src/leveldb/libleveldb.a; $$PWD/src/leveldb ; $(MAKE) clean

# regenerate src/build.h
!windows|contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

contains(USE_O3, 1) {
    message(Building O3 optimization flag)
    QMAKE_CXXFLAGS_RELEASE -= -O2
    QMAKE_CFLAGS_RELEASE -= -O2
    QMAKE_CXXFLAGS += -O3
    QMAKE_CFLAGS += -O3
}

*-g++-32 {
    message("32 platform, adding -msse2 flag")

    QMAKE_CXXFLAGS += -msse2
    QMAKE_CFLAGS += -msse2
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter -Wstack-protector


# Input
DEPENDPATH += src src/json

HEADERS += \
    src/allocators.h \
    src/base58.h \
    src/bignum.h \
    src/clientversion.h \
    src/init.h \
    src/key.h \
    src/keystore.h \
    src/main.h \
    src/script.h \
    src/serialize.h \
    src/strlcpy.h \
    src/sync.h \
    src/threadsafety.h \
    src/uint256.h \
    src/ui_interface.h \
    src/version.h \
    src/global.h \
    src/batchscanner.h \
    src/validation.h \
    src/tinyformat.h \
    src/fs.h \
    src/util/util.h \
    src/util/utilmoneystr.h \
    src/util/utilstrencodings.h \
    src/util/utiltime.h \
    src/util/utilexceptions.h \
    src/amount.h \
    src/noui.h \
    src/json/json_spirit.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_writer_template.h \
    src/crypto/hash.h \
    src/crypto/scrypt.h \
    src/rpc/bitcoinrpc.h \
    src/chain/blockindex.h \
    src/chain/block.h \
    src/chain/chain.h \
    src/chain/checkpoints.h \
    src/wallet/db.h \
    src/tx/disk.h \
    src/mining/kernel.h \
    src/wallet/crypter.h \
    src/tx/mempool.h \
    src/tx/merkletx.h \
    src/chain/locator.h \
    src/wallet/walletdb.h \
    src/wallet/wallet.h \
    src/tx/txdb-leveldb.h \
    src/util/random.h \
    src/crypto/pbkdf2.h \
    src/mining/miner.h \
    src/wallet/coincontrol.h \
    src/tx/tx.h \
    src/tx/outpoint.h \
    src/tx/inpoint.h \
    src/p2p/addrman.h \
    src/p2p/compat.h \
    src/p2p/mruset.h \
    src/p2p/netaddr.h \
    src/p2p/net.h \
    src/p2p/netutils.h \
    src/p2p/node.h \
    src/p2p/protocol.h \
    src/p2p/proxyutils.h \
    src/p2p/service.h \
    src/p2p/subnet.h \
    src/p2p/socketutils.h \
    src/p2p/cnodestate.h \
    src/shutdown.h \
    src/threads.h \
    src/p2p/connman.h \
    src/p2p/addrdb.h \
    src/crypto/common.h \
    src/crypto/crypto_endian.h \
    src/crypto/byteswap.h \
    src/prevector.h \
    src/arith_uint256.h \
    src/p2p/signals.h \
    src/p2p/bloom.h \
    src/crypto/sha256.h \
    src/crypto/chacha20.h \
    src/p2p/messages.h \
    src/limitedmap.h \
    src/scheduler.h \
    src/reverselock.h \
    src/p2p/processing.h

# organize compiles of cpp files by section, this seems to be a logical order where the files lower down generally depend
# on the ones higher up. also helps to observe how far into the compile process we are
SOURCES += \
    src/util/util.cpp \
    src/util/utiltime.cpp \
    src/util/utilstrencodings.cpp \
    src/util/utilmoneystr.cpp \
    src/util/utilexceptions.cpp \
    src/util/random.cpp \
#
    src/uint256.cpp \
    src/arith_uint256.cpp \
    src/fs.cpp \
    src/global.cpp \
    src/init.cpp \
    src/key.cpp \
    src/keystore.cpp \
    src/main.cpp \
    src/noui.cpp \
    src/script.cpp \
    src/sync.cpp \
    src/version.cpp \
    src/shutdown.cpp \
    src/threads.cpp \
    src/scheduler.cpp \
    src/validation.cpp \
#
    src/crypto/sha256.cpp \
    src/crypto/chacha20.cpp \
    src/crypto/hash.cpp \
    src/crypto/scrypt.cpp \
    src/crypto/pbkdf2.cpp \
#
    src/chain/block.cpp \
    src/chain/blockindex.cpp \
    src/chain/chain.cpp \
    src/chain/checkpoints.cpp \
    src/chain/locator.cpp \
#
    src/tx/txdb-leveldb.cpp \
    src/tx/mempool.cpp \
    src/tx/merkletx.cpp \
    src/tx/tx.cpp \
    src/tx/disk.cpp \
    src/tx/outpoint.cpp \
    src/tx/inpoint.cpp \
#
    src/wallet/wallet.cpp \
    src/wallet/walletdb.cpp \
    src/wallet/crypter.cpp \
    src/wallet/db.cpp \
#
    src/mining/kernel.cpp \
    src/mining/miner.cpp \
#
    src/p2p/addrman.cpp \
    src/p2p/net.cpp \
    src/p2p/netaddr.cpp \
    src/p2p/netutils.cpp \
    src/p2p/node.cpp \
    src/p2p/subnet.cpp \
    src/p2p/socketutils.cpp \
    src/p2p/service.cpp \
    src/p2p/proxyutils.cpp \
    src/p2p/protocol.cpp \
    src/p2p/cnodestate.cpp \
    src/p2p/addrdb.cpp \
    src/p2p/signals.cpp \
    src/p2p/bloom.cpp \
    src/p2p/connman.cpp \
    src/p2p/messages.cpp \
    src/p2p/processing.cpp \
#
    src/rpc/bitcoinrpc.cpp \
    src/rpc/rpcblockchain.cpp \
    src/rpc/rpcdump.cpp \
    src/rpc/rpcmining.cpp \
    src/rpc/rpcrawtransaction.cpp \
    src/rpc/rpcnet.cpp \
    src/rpc/rpcwallet.cpp



CODECFORTR = UTF-8


isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}

TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# platform specific defaults, if not overridden on command line
isEmpty(BOOST_LIB_SUFFIX) {
    macx:BOOST_LIB_SUFFIX = -mt
    windows:BOOST_LIB_SUFFIX = -mgw48-mt-s-1_550
}

isEmpty(BOOST_THREAD_LIB_SUFFIX) {
    BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}

isEmpty(BDB_LIB_PATH) {
    macx:BDB_LIB_PATH = /opt/local/lib/db48
}

isEmpty(BDB_LIB_SUFFIX) {
    macx:BDB_LIB_SUFFIX = -4.8
}

isEmpty(BDB_INCLUDE_PATH) {
    macx:BDB_INCLUDE_PATH = /opt/local/include/db48
}

isEmpty(BOOST_LIB_PATH) {
    macx:BOOST_LIB_PATH = /opt/local/lib
}

isEmpty(BOOST_INCLUDE_PATH) {
    macx:BOOST_INCLUDE_PATH = /opt/local/include
}

windows:DEFINES += WIN32

windows:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT BOOST_THREAD_PROVIDES_GENERIC_SHARED_MUTEX_ON_WIN
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt
}

macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:TARGET = "ECCoind"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH $$LIBEVENT_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,) $$join(LIBEVENT_LIB_PATH,,-L,)
LIBS += -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX
# -lgdi32 has to happen after -lcrypto (see  #681)
win32:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX
win32:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX
macx:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX
!windows:!macx {
    LIBS += -lboost_chrono
}



contains(RELEASE, 1) {
    !windows:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}

system($$QMAKE_LRELEASE -silent $$_PRO_FILE_)

DISTFILES +=

