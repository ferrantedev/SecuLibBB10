##This works by executing the following command to generate makefiles in OSX for target BB10
##TODO: Does not work from GUI!!
##cmake ../src -DCMAKE_TOOLCHAIN_FILE="../toolchains/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles" -DOPENSSL_CRYPTO_LIBRARY=/Applications/Momentics.app/target_10_3_1_995/qnx6/armle-v7/usr/lib -DOPENSSL_INCLUDE_DIR=/Applications/Momentics.app/target_10_3_1_995/qnx6/usr/include -DCMAKE_ECLIPSE_VERSION=4.3.2
##
cmake_minimum_required (VERSION 2.6)
project (Seculib)

set( ENV{BBNDK_PATH} /Applications/Momentics.app )
set(ENV{QNX_HOST} "${BBNDK_PATH}/host_10_3_1_12/darwin/x86")
set(ENV{QNX_TARGET} "${BBNDK_PATH}/target_10_3_1_995/qnx6")
set(ENV{QTVERSION} "4")
set(ENV{ARCH} "armle-v7")
set(ENV{TARGET} "qnx6")
set(ENV{QNX_CONFIGURATION} "${BBNDK_PATH}/.rim/bbndk")
set(ENV{MAKEFLAGS} "-I${BBNDK_PATH}/target_10_3_1_995/qnx6/usr/include")
set(ENV{PATH} "${BBNDK_PATH}/host_10_3_1_12/darwin/x86/usr/bin:${BBNDK_PATH}/.rim/bbndk/bin:${BBNDK_PATH}/host_10_3_1_12/darwin/x86/usr/python32/bin:$ENV{PATH}")

set(env{QT_PLUGIN_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt5/plugins")
set(ENV{QT_LIB_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt5/lib")
set(ENV{QML2_IMPORT_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt5/qml")
set(ENV{LD_LIBRARY_PATH} "${BBNDK_PATH}/host_10_3_1_12/darwin/x86/usr/lib:${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt$QTVERSION/lib:$ENV{LD_LIBRARY_PATH}")
set(ENV{CPUVARDIR} "armle-v7")
set( BLACKBERRY_TARGET_ROOT "$ENV{QNX_TARGET}" )

list( APPEND BLACKBERRY_SYSTEM_INCLUDE_DIRS "${BLACKBERRY_TARGET_ROOT}/qnx6/usr/include")

SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_LINK_FLAGS}" )
SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_LINK_FLAGS}")
if (APPLE)
    set( ENV{BBNDK_PATH} /Applications/Momentics.app )
    set(ENV{QNX_HOST} "${BBNDK_PATH}/host_10_3_1_12/darwin/x86")
    set(ENV{QNX_TARGET} "${BBNDK_PATH}/target_10_3_1_995/qnx6")
    set(ENV{QTVERSION} "4")
    set(ENV{ARCH} "armle-v7")
    set(ENV{TARGET} "qnx6")
    set(ENV{QNX_CONFIGURATION} "${BBNDK_PATH}/.rim/bbndk")
    set(ENV{MAKEFLAGS} "-I${BBNDK_PATH}/target_10_3_1_995/qnx6/usr/include")
    set(ENV{PATH} "${BBNDK_PATH}/host_10_3_1_12/darwin/x86/usr/bin:${BBNDK_PATH}/.rim/bbndk/bin:${BBNDK_PATH}/host_10_3_1_12/darwin/x86/usr/python32/bin:$ENV{PATH}")

    set(env{QT_PLUGIN_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt5/plugins")
    set(ENV{QT_LIB_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt5/lib")
    set(ENV{QML2_IMPORT_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt5/qml")
    set(ENV{LD_LIBRARY_PATH} "${BBNDK_PATH}/host_10_3_1_12/darwin/x86/usr/lib:${BBNDK_PATH}/target_10_3_1_995/qnx6/../darwin/x86/usr/lib/qt$QTVERSION/lib:$ENV{LD_LIBRARY_PATH}")
    set(ENV{CPUVARDIR} "armle-v7")
    set( BLACKBERRY_TARGET_ROOT "$ENV{QNX_TARGET}" )

    list( APPEND BLACKBERRY_SYSTEM_INCLUDE_DIRS "${BLACKBERRY_TARGET_ROOT}/qnx6/usr/include")

    SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_LINK_FLAGS}" )
    SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_LINK_FLAGS}")

endif ()

if(UNIX AND NOT APPLE)

    set(ENV{QNX_HOST} "/home/z/bbndk/host_10_3_1_12/linux/x86")
    set(ENV{QNX_TARGET} "/home/z/bbndk/target_10_3_1_995/qnx6")
    set(ENV{QTVERSION} "4")
    set(ENV{ARCH} "armle-v7")
    set(ENV{TARGET} "qnx6")
    set(ENV{QNX_CONFIGURATION} "/home/z/.rim/bbndk")
    set(ENV{MAKEFLAGS} "-I/home/z/bbndk/target_10_3_1_995/qnx6/usr/include")
    set(ENV{PATH} "/home/z/bbndk/host_10_3_1_12/linux/x86/usr/bin:/home/z/.rim/bbndk/bin:/home/z/bbndk/host_10_3_1_12/linux/x86/usr/python32/bin:$ENV{PATH}")

    set(env{QT_PLUGIN_PATH} "/home/z/bbndk/target_10_3_1_995/qnx6/../linux/x86/usr/lib/qt5/plugins")
    set(ENV{QT_LIB_PATH} "/home/z/bbndk/target_10_3_1_995/qnx6/../linux/x86/usr/lib/qt5/lib")
    set(ENV{QML2_IMPORT_PATH} "/home/z/bbndk/target_10_3_1_995/qnx6/../linux/x86/usr/lib/qt5/qml")
    set(ENV{LD_LIBRARY_PATH} "/home/z/bbndk/host_10_3_1_12/linux/x86/usr/lib:/home/z/bbndk/target_10_3_1_995/qnx6/../linux/x86/usr/lib/qt$QTVERSION/lib:$ENV{LD_LIBRARY_PATH}")
    set(ENV{CPUVARDIR} "armle-v7")
    set( BLACKBERRY_TARGET_ROOT "$ENV{QNX_TARGET}" )

    list( APPEND BLACKBERRY_SYSTEM_INCLUDE_DIRS "${BLACKBERRY_TARGET_ROOT}/qnx6/usr/include")

    project (ZrtpService)

endif()

if(WIN32)
	include_directories("C:\\OpenSSL-Win32\\include")
endif()

include_directories("${PROJECT_BINARY_DIR}")

include_directories ("${PROJECT_SOURCE_DIR}/MimeParser/include" "${PROJECT_SOURCE_DIR}/SecuCrypto/include")

find_package(OpenSSL)
add_subdirectory (MimeParser) 
add_subdirectory(SecuCrypto)

# add the executable
#add_executable(Seculib src/SecuLib.cpp)
#target_link_libraries (Seculib MimeParser SecuCrypto libc)