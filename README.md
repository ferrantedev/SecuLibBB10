# SecuLibBB10
Cryptographic and MIME parsing library for Blackberry 10 based on OpenSSL written in C 98 and C++ 11

The most important functions in this library are:
- PKCS 1 (Public and Private key generation)
- PKCS 8 (Private key conversion to an encrypted format )
- PKCS 10 (Certificate sign request generation)
- SMIME sign and verify
- SMIME encrypt and decrypt 
- PBKDF2 derivation function`
- AES CBC encryption and decryption
- AES GCM encryption and decryption
- A rudimentary MIME parser and generator


# Description 
This library has been compiled and used in Linux and Windows. The compilation steps are similar, you just need 
to link OpenSSL's compiled library files (.so or .dylib) and include the header files for symbol resolution.
Also you would need to tweak CMake's options depending on your target platform.

# Requirements:
- Blackberry 10.3 SDK, included in the Momentics IDE distributed by Blackberry


#  Usage Linux:
   $ source /absolute/path/to/the/bbndk/bbndk-env.sh
   $ mkdir build
   $ cd build
   $ cmake .. -DCMAKE_TOOLCHAIN_FILE="../CMake/toolchain/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DOGRE_DEPENDENCIES_DIR="../BlackBerryDependencies" -DOGRE_BUILD_RENDERSYSTEM_GLES2=TRUE -DOGRE_STATIC=TRUE  -DOGRE_BUILD_COMPONENT_PAGING=TRUE -DOGRE_BUILD_COMPONENT_TERRAIN=TRUE -DOGRE_BUILD_COMPONENT_RTSHADERSYSTEM=TRUE -DOGRE_BUILD_PLUGIN_BSP=FALSE -DOGRE_BUILD_PLUGIN_PCZ=FALSE -DOGRE_BUILD_RENDERSYSTEM_GLES=FALSE -DOGRE_BUILD_TESTS=FALSE -DOGRE_BUILD_TOOLS=FALSE -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles"
   $ make -j8

#  Usage Mac:
   Same as the steps on Linux

#  Usage Windows:
   > /absolute/path/to/the/bbndk/bbndk-env.bat
   > mkdir build
   > cd build
   > cmake .. -DCMAKE_TOOLCHAIN_FILE="../CMake/toolchain/blackberry.toolchain.cmake" -DTargetPlatform="BlackBerry" -DBLACKBERRY_ARCHITECTURE=arm -DOGRE_DEPENDENCIES_DIR="../BlackBerryDependencies" -DOGRE_BUILD_RENDERSYSTEM_GLES2=TRUE -DOGRE_STATIC=TRUE  -DOGRE_BUILD_COMPONENT_PAGING=TRUE -DOGRE_BUILD_COMPONENT_TERRAIN=TRUE -DOGRE_BUILD_COMPONENT_RTSHADERSYSTEM=TRUE -DOGRE_BUILD_PLUGIN_BSP=FALSE -DOGRE_BUILD_PLUGIN_PCZ=FALSE -DOGRE_BUILD_RENDERSYSTEM_GLES=FALSE -DOGRE_BUILD_TESTS=FALSE -DOGRE_BUILD_TOOLS=FALSE -DCMAKE_VERBOSE_MAKEFILE=TRUE -G "Eclipse CDT4 - Unix Makefiles"
   > make -j8


