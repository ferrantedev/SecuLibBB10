cmake_minimum_required (VERSION 2.6)
project (Seculib)
include_directories("${PROJECT_BINARY_DIR}")

include_directories ("${PROJECT_SOURCE_DIR}/MimeParser/include" "${PROJECT_SOURCE_DIR}/SecuCrypto/include" "C:\\OpenSSL-Win32\\include")

find_package(OpenSSL)
add_subdirectory (MimeParser) 
add_subdirectory(SecuCrypto)

# add the executable
add_executable(Seculib src/SecuLib.cpp)
target_link_libraries (Seculib MimeParser SecuCrypto)