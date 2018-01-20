cmake_minimum_required(VERSION 3.9)
project(SecuCrypto VERSION 1.0.1 DESCRIPTION "Secucom crypto library")

include_directories ("${PROJECT_SOURCE_DIR}/include")

ADD_LIBRARY(SecuCrypto STATIC src/SecuCrypto.cpp include/SecuCrypto.hpp )
find_package(OpenSSL)
set_target_properties(SecuCrypto PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(SecuCrypto PROPERTIES SOVERSION 1)


target_include_directories(SecuCrypto PRIVATE include)

set_target_properties(SecuCrypto PROPERTIES PUBLIC_HEADER include/SecuCrypto.hpp)

configure_file(SecuCrypto.pc.in SecuCrypto.pc @ONLY)

IF(${TARGET_HOST} EQUAL "WINDOWS")
	include_directories( "\c\OpenSSL-Win32\include")
	target_link_libraries(SecuCrypto "\c\OpenSSL-Win32/lib/VC/libssl32MDd.lib" "\c\OpenSSL-Win32/lib/VC/libcrypto32MD.lib")
endif()