##This works by executing the following command to generate makefiles in OSX for target BB10
##TODO: Does not work from GUI!!
##cmake ../src -DCMAKE_TOOLCHAIN_FILE="../toolchains/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles" -DOPENSSL_CRYPTO_LIBRARY=/Applications/Momentics.app/target_10_3_1_995/qnx6/armle-v7/usr/lib -DOPENSSL_INCLUDE_DIR=/Applications/Momentics.app/target_10_3_1_995/qnx6/usr/include -DCMAKE_ECLIPSE_VERSION=4.3.2
##

##On windows host
##/d/cmake/bin/cmake.exe ../src -DCMAKE_TOOLCHAIN_FILE="../toolchains/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles" -DOPENSSL_CRYPTO_LIBRARY=/d/momentics/bbndk/target_10_3_1_995/qnx6/armle-v7/usr/lib -DOPENSSL_INCLUDE_DIR=/d/momentics/bbndk/target_10_3_1_995/qnx6/usr/include -DCMAKE_ECLIPSE_VERSION=4.3.2 -DCMAKE_MAKE_PROGRAM=make
cmake_minimum_required (VERSION 2.6)
project (CryptoTests)

include_directories("${PROJECT_BINARY_DIR}")

include_directories ("${PROJECT_SOURCE_DIR}/SecuCrypto/include")
find_package(OpenSSL)
# add the executable
add_executable(CryptoTests src/CryptoTests.cpp)
target_link_libraries (CryptoTests SecuCrypto ${OPENSSL_LIBRARIES}) 
##maybe should add libc to target_link_libraries in unix env