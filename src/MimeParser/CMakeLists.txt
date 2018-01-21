cmake_minimum_required(VERSION 3.9)
project(MimeParser VERSION 1.0.1 DESCRIPTION "Simple Mime Parser")

include_directories ("${PROJECT_SOURCE_DIR}/include")

ADD_LIBRARY( MimeParser STATIC src/MimeParser.cpp include/MimeParser.hpp )

set_target_properties(MimeParser PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(MimeParser PROPERTIES SOVERSION 1)


target_include_directories(MimeParser PRIVATE include)

set_target_properties(MimeParser PROPERTIES PUBLIC_HEADER include/MimeParser.hpp)

configure_file(MimeParser.pc.in MimeParser.pc @ONLY)

find_package(OpenSSL)
IF(WINDOWS_TARGET)
	include_directories ( "C:\\OpenSSL-Win32\\include")
	target_link_libraries(MimeParser "C:/OpenSSL-Win32/lib/VC/libssl32MDd.lib" "C:/OpenSSL-Win32/lib/VC/libcrypto32MD.lib")
ELSE() 
target_link_libraries(MimeParser libc)
ENDIF()