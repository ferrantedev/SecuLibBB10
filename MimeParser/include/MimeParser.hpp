/* Copyright (C) Secucom, Inc - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by j11, September 2016
*/

#ifndef MIMEPARSER_HPP_
#define MIMEPARSER_HPP_
#include <fstream>
#include <memory>

	#ifdef _WIN32
	#include <io.h>
	#include <direct.h>  
	#include <stdlib.h>  
	#endif

	#ifdef __LINUX__
	#include <unistd.h>
	#endif

#include <string>
#include <iostream>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <iterator>
#include <stdio.h>
#include <stdint.h>

namespace mime {
	/*
	* @description This file contains utility functions for processing MIME data structures and for constructing MIME them as well.
	*
	*/
	extern std::vector<std::string> receivedAttachmentList;
	std::vector<unsigned char> create_MIME(std::vector<char> pData, std::vector<std::string> attachment_list);
	std::vector<char> find_format(std::string * pFilepath);
	std::string find_simple_format(std::string pFilepath);
	void write_buffer_to_file(const char *pFilepath, unsigned char * pBuffer, size_t pFileLength);
	int uuid_v4_gen(char * pBuffer);
	bool parse_multipart_content(const char * pFileToLoad, const char * pSavePath, const unsigned char * pData);
	std::vector<unsigned char> parse_boundary(std::vector<unsigned char> & pBuffer);
	std::vector<unsigned char> load_attachment(const char * pFilepath);
	std::vector<unsigned char> get_content_header(std::vector<unsigned char> & pContent);
	std::string identify_extension(std::vector<unsigned char> & pHeader);
	std::string get_attachment_name(std::vector<unsigned char> & pHeader);
	std::vector<unsigned char> erase_header_from_content(std::vector<unsigned char> & pContent, std::vector<unsigned char> & pHeader);
	void save_attachment_to_fs(std::string pSavePath, std::vector<unsigned char> & pContent_body, std::string pFile_name);

	struct Constants {
		static const int AUTH_MODE_MASTER_ONLY;
		static const int AUTH_MODE_ALL_PASSWORDS;
		static const int SYMMETRIC_PASSWORD_ITERATION_COUNT;
		static const int SYMMETRIC_ENCRIPTION_IV_LENGTH;

		static const int AES_GCM_KEY_BYTE_SIZE;
		static const int AES_GCM_AUTH_TAG_BYTE_SIZE;
		static const int AES_GCM_IV_BYTE_SIZE;
		static const char * TEMP_ENCRYPTED_DATA_OUTPATH;
		static const char * PRIVATE_KEY_BASE_PATH;
		static const char * PULIC_KEY_BASE_PATH;
		static const char * CSR_PATH;
		static const char * PUBLIC_CERTIFICATE_PATH;
		static const char * PRIVATE_CERTIFICATE_PATH;
		static const char * SQLITE_CONNECTION;
		static const char * DATABASE_FILE;
		static const char * PKI_URL;
		static const char * PKI_POST_CSR_PATH;
		static const char * PKI_CHECK_CSR_STATUS_PATH;
		static const char * PKI_CHECK_RECIPIENT_PATH;
		static const char * CA_CERT_PATH;
		static const char * RECIPIENTS_BASE_PATH;
		static const char * SUB_CA_CERT_PATH;
		static const char * PASSWORD_KEEPER_PATH;
		static const std::string FILE_EXTENSIONS[649];
		static const std::string CONTENT_TYPES[649];


	};
}
#endif
