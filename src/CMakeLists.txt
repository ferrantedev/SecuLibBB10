##This works by executing the following command to generate makefiles in OSX for target BB10
##TODO: Does not work from GUI!!
##cmake ../src -DCMAKE_TOOLCHAIN_FILE="../toolchains/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles" -DOPENSSL_CRYPTO_LIBRARY=/Applications/Momentics.app/target_10_3_1_995/qnx6/armle-v7/usr/lib -DOPENSSL_INCLUDE_DIR=/Applications/Momentics.app/target_10_3_1_995/qnx6/usr/include -DCMAKE_ECLIPSE_VERSION=4.3.2
##

##On windows host
##/d/cmake/bin/cmake.exe ../src -DCMAKE_TOOLCHAIN_FILE="../toolchains/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles" -DOPENSSL_CRYPTO_LIBRARY=/d/momentics/bbndk/target_10_3_1_995/qnx6/armle-v7/usr/lib -DOPENSSL_INCLUDE_DIR=/d/momentics/bbndk/target_10_3_1_995/qnx6/usr/include -DCMAKE_ECLIPSE_VERSION=4.3.2 -DCMAKE_MAKE_PROGRAM=make -DBB10_TARGET=ON -DWINDOWS_TARGET=OFF

cmake_minimum_required (VERSION 2.6)
project (Seculib)
set(TARGET_HOST "BB10")
option(WINDOWS_TARGET "The target host we are building for is WIndows" ON)
option(BB10_TARGET "The target host we are building for is Bb10" OFF)

IF (WIN32)
	if(WINDOWS_TARGET)
		include_directories("C:/OpenSSL-Win32/include")
	else()
		##Then the target host is Blackberry 10 (BB10)
		set( ENV{BBNDK_PATH} /d/momentics/bbndk)
		set(ENV{QNX_HOST} "${BBNDK_PATH}/host_10_3_1_12/win32/x86")
		set(ENV{QNX_TARGET} "${BBNDK_PATH}/target_10_3_1_995/qnx6")
		set(ENV{QTVERSION} "4")
		set(ENV{ARCH} "armle-v7")
		set(ENV{TARGET} "qnx6")
		set(ENV{QNX_CONFIGURATION} "${BBNDK_PATH}/.rim/bbndk")
		set(ENV{MAKEFLAGS} "-I${BBNDK_PATH}/target_10_3_1_995/qnx6/usr/include")
		set(ENV{PATH} "${BBNDK_PATH}/host_10_3_1_12/win32/x86/usr/bin:${BBNDK_PATH}/.rim/bbndk/bin:${BBNDK_PATH}/host_10_3_1_12/win32/x86/usr/python32/bin:$ENV{PATH}")

		set(env{QT_PLUGIN_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../win32/x86/usr/lib/qt5/plugins")
		set(ENV{QT_LIB_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../win32/x86/usr/lib/qt5/lib")
		set(ENV{QML2_IMPORT_PATH} "${BBNDK_PATH}/target_10_3_1_995/qnx6/../win32/x86/usr/lib/qt5/qml")
		set(ENV{LD_LIBRARY_PATH} "${BBNDK_PATH}/host_10_3_1_12/win32/x86/usr/lib:${BBNDK_PATH}/target_10_3_1_995/qnx6/../win32/x86/usr/lib/qt$QTVERSION/lib:$ENV{LD_LIBRARY_PATH}")
		set(ENV{CPUVARDIR} "armle-v7")
		set( BLACKBERRY_TARGET_ROOT "$ENV{QNX_TARGET}" )
		
		list( APPEND BLACKBERRY_SYSTEM_INCLUDE_DIRS "${BLACKBERRY_TARGET_ROOT}/qnx6/usr/include")
		
		SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_LINK_FLAGS}" )
		SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_LINK_FLAGS}")
	endif()
ELSE()
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

ENDIF()


if(UNIX AND NOT APPLE)
	##For unix host

endif()


include_directories("${PROJECT_BINARY_DIR}")

include_directories ("${PROJECT_SOURCE_DIR}/MimeParser/include" "${PROJECT_SOURCE_DIR}/SecuCrypto/include")

find_package(OpenSSL)
add_subdirectory (MimeParser) 
add_subdirectory(SecuCrypto)
add_subdirectory(CryptoTests)
