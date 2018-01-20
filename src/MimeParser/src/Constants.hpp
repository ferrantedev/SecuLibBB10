/*
 * Constants.hpp
 *
 *  Created on: 24/10/2016
 *      Author: lorenzo
 */

#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP
#include <iostream>


namespace util {

    /*
     * @description This file contains the constants used throughout the application.
     */

    struct Constants {
        static const int AUTH_MODE_MASTER_ONLY;
        static const int AUTH_MODE_ALL_PASSWORDS;
        static const int SYMMETRIC_PASSWORD_ITERATION_COUNT;
        static const int SYMMETRIC_ENCRIPTION_IV_LENGTH;

        static const int AES_GCM_KEY_BYTE_SIZE;
        static const int AES_GCM_AUTH_TAG_BYTE_SIZE;
        static const int AES_GCM_IV_BYTE_SIZE;

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
        static std::string CONTENT_TYPES[649];

        enum APP_STATUS {
             NO_MASTER_PASSWORD = 0,
             NO_SYMMETRIC = 1,
             NO_KEYS = 2,
             KEYS_READY = 3,
             CSR_READY = 4,
             CSR_SIGN_PENDING = 5,
             PUBLIC_CERT_READY = 6,
             PRIVATE_CERT_READY = 7,
             CERTIFICATES_REVOKED = 8,
             CERTIFICATES_ERASED = 9
         };
    };
}


#endif /* CONSTANTS_H_ */
