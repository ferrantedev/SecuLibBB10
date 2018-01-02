/* Copyright (C) Secucom, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by j11, September 2016
 */

#include "SecuCrypto.hpp"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

#include <fstream>
#include <algorithm>

#include "MimeParser.hpp"

using namespace mime;

namespace crypto
{

    /*
     * An array of filepaths, when SMIME sign is called, it will load all the attachments
     * into a multipart/mixed message structure.
     */
    std::vector<std::string> attachmentList;


    /*
     * PKCS1 generation function, basically will output an RSA key pair.
     * @param pPrivateKeyPath the path where the private key will be saved.
     * @param pPublicKeyPath the path where the public key will be saved.
     * @param pPassword the password for the private key, (PKCS8)
     * @return Will return True if generation succeeded and False otherwise.
     */
    bool generate_PKCS1(const char * pPrivateKeyPath, const char * pPublicKeyPath, char * pPassword,
            int pBitSize)
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        char * error = NULL;
        bool success = true;
        RSA * rsa = RSA_new();
        BIGNUM * bn = BN_new();
        EVP_PKEY * pkey = EVP_PKEY_new();

        BIO * rsaPublic = BIO_new_file(pPublicKeyPath, "w");
        BIO * rsaPrivate = BIO_new_file(pPrivateKeyPath, "w");

        if (!BN_set_word(bn, RSA_F4)) {
            success = false;
            goto err;
        }

        if (!RSA_generate_key_ex(rsa, pBitSize, bn, NULL)) {
            success = false;
            goto err;
        }

        //Set private key into pkey from rsa
        if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
            success = false;
            goto err;
        }

        if (!PEM_write_bio_RSAPublicKey(rsaPublic, rsa)) {
            success = false;
            goto err;
        }

        if (!PEM_write_bio_PKCS8PrivateKey(rsaPrivate, pkey, EVP_aes_256_cbc(), NULL, NULL, NULL,
                pPassword)) {
            success = false;
            goto err;
        }

        err: if (!success) {
            error = ERR_error_string(ERR_get_error(), NULL);
            printf(error);
        }

        RSA_free(rsa);
        BN_free(bn);
        EVP_PKEY_free(pkey);
        BIO_free(rsaPublic);
        BIO_free(rsaPrivate);
        return success;
    }


    /*
     * Attempts to decrypt an encrypted private key (PKCS8), this is used to verify that the password is correct.
     * @param pPassword The password that will be used to decrypt the key.
     * @param pPrivateKeyPath The file path of the PKCS8 file.
     * @return Will return True if decryption succeeded (password correct) and False otherwise (password incorrect).
     */
    bool try_open_PKCS8(const char* pPassword, const char * pPrivateKeyPath)
    {
        bool success = true;
        OpenSSL_add_all_algorithms();
        BIO * file = NULL;
        X509_SIG * p8 = NULL;
        PKCS8_PRIV_KEY_INFO * p8inf = NULL;
        EVP_PKEY* pkey = NULL;

        file = BIO_new_file(pPrivateKeyPath, "r");
        if (!file) {
            success = false;
            goto err;
        }

        PEM_read_bio_PKCS8(file, &p8, 0, NULL);
        if (!p8) {
            success = false;
            goto err;
        }

        p8inf = PKCS8_decrypt(p8, pPassword, strlen(pPassword));
        if (!p8inf) {
            success = false;
            goto err;
        }

        pkey = EVP_PKCS82PKEY(p8inf);
        if (!pkey) {
            success = false;
            goto err;
        }

        err: if (!success) {
           printf("Cannot open PKCS8 file\n");
        }

        X509_SIG_free(p8);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        BIO_free(file);
        EVP_PKEY_free(pkey);
        return success;
    }


    /*
     * Generates a Certificate Sign Request (CSR or PKCS10) with the supplied parameters.
     * The CSR will be generated in PEM format.
     * @param pPrivateKeyPath The file path of the private key.
     * @param pPublicKeyPath The file path of the public key.
     * @param pCSRSavePath The file path where the CSR will be saved.
     * @oaram pInfo A struct containing CSR information such as: Country, City, Organizational Unit (OU), Email, etc
     * @param pPassword The encrypted private key password.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool generate_PKCS10(const char * pPrivateKeyPath, const char * pPublicKeyPath,
            const char * pCSRSavePath, const CSR_Requred_Fields * pInfo, const char * pPassword)
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        char * error = NULL;
        bool success = true;
        int version = 1;
        X509_REQ *x509_req = NULL;
        X509_NAME *x509_name = NULL;
        EVP_PKEY *pKey = NULL;
        BIO *out = NULL;
        X509_SIG * p8 = NULL;
        PKCS8_PRIV_KEY_INFO * p8inf = NULL;

        //BIO * publicPem = BIO_new_file(pPublicKeyPath, "r");
        BIO * privatePem = NULL;

        //Read Private key
        privatePem = BIO_new_file(pPrivateKeyPath, "r");
        if (!privatePem) {
            success = false;
            goto err;
        }

        PEM_read_bio_PKCS8(privatePem, &p8, 0, NULL);
        if (!p8) {
            success = false;
            goto err;
        }

        p8inf = PKCS8_decrypt(p8, pPassword, strlen(pPassword));
        if (!p8inf) {
            success = false;
            goto err;
        }

        pKey = EVP_PKCS82PKEY(p8inf);
        if (!pKey) {
            success = false;
            goto err;
        }

        //Read public rsa key
        //rsa = PEM_read_bio_RSAPublicKey(publicPem, NULL, NULL, NULL);

        x509_req = X509_REQ_new();
        if (!X509_REQ_set_version(x509_req, version)) {
            success = false;
            goto err;
        }

        // Set subject and details
        x509_name = X509_REQ_get_subject_name(x509_req);

        if (!X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC,
                (const unsigned char*) pInfo->country, -1, -1, 0)) {
            success = false;
            goto err;
        }

        if (!X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC,
                (const unsigned char*) pInfo->province, -1, -1, 0)) {
            success = false;
            goto err;
        }

        if (!X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC,
                (const unsigned char*) pInfo->city, -1, -1, 0)) {
            success = false;
            goto err;
        }

        if (!X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC,
                (const unsigned char*) pInfo->org, -1, -1, 0)) {
            success = false;
            goto err;
        }

        if (!X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC,
                (const unsigned char*) pInfo->ou, -1, -1, 0)) {
            success = false;
            goto err;
        }

        if (!X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
                (const unsigned char*) pInfo->common, -1, -1, 0)) {
            success = false;
            goto err;
        }

        if (!X509_REQ_set_pubkey(x509_req, pKey)) {
            success = false;
            goto err;
        }

        // Set sign of request
        if (!X509_REQ_sign(x509_req, pKey, EVP_sha512())) {
            success = false;
            goto err;
        }

        out = BIO_new_file(pCSRSavePath, "w");
        if (!PEM_write_bio_X509_REQ(out, x509_req)) {
            success = false;
            goto err;
        }

        err: if (!success) {
            error = ERR_error_string(ERR_get_error(), NULL);
            printf(error);
        }

        X509_REQ_free(x509_req);
        BIO_free_all(out);
        // BIO_free(publicPem);
        BIO_free(privatePem);
        EVP_PKEY_free(pKey);
        X509_SIG_free(p8);
        PKCS8_PRIV_KEY_INFO_free(p8inf);

        return success;
    }

    /*
     * Generates a multipart/mixed message and then signs it with the supplied private key (PKCS8).
     * First, will derive the attachments list and the plain text data to create_MIME function, which will return a multipart/mixed message.
     * Second, will decrypt the private key with the supplied pPassword.
     * Third, will perform the sign operation on the multipart/mixed message buffer.
     * @param pData The plain text data to be signed.
     * @param pPassword The password to be used for decrypting the private key (PKCS8).
     * @param pPrivateKeyPath The file path of the private key (PKCS8).
     * @param pPublicCertPath The file path of the public certificate.
     * @param pOutputPath The file path where the signed multipart/mixed message will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_sign(const char * pData, const char * pPassword, const char * pPrivateKeyPath,
            const char * pPublicCertPath, const char * pOutputPath)
    {
        char * error = NULL;
        OpenSSL_add_all_algorithms();
        int flags = PKCS7_BINARY | PKCS7_STREAM; // | PKCS7_NOCERTS;
        bool success = true;
        BIO * subCaBIO = NULL;
        BIO * inBIO = NULL;
        BIO * outBIO = NULL;
        BIO * publicCertBIO = NULL;
        BIO * privateKeyBIO = NULL;
        X509 * publicCert = NULL;
        X509 * subCaX509 = NULL;
        EVP_PKEY * pKey = NULL;
        STACK_OF(X509) * ca = NULL;
        PKCS7 *p7 = NULL;
        X509_SIG * p8 = NULL;
        PKCS8_PRIV_KEY_INFO * p8inf = NULL;

        int size = strlen(pData);
        std::vector<char> plain_text_data(pData, pData + size);
        inBIO = BIO_new(BIO_s_mem());
        std::vector<unsigned char> data = create_MIME(plain_text_data, crypto::attachmentList);

        if (data.empty()) {
			printf("ERROR: Data to be signed is empty, aborting\n");
            success = false;
            goto err;
        }

        BIO_write(inBIO, &data[0], data.size());
        if (!inBIO) {
			printf("ERROR: Cannot write MIME and data to buffer\n");
            success = false;
            goto err;
        }

        /*
         * Read the sub ca cert
         */

        subCaBIO = BIO_new_file("app/native/assets/certs/sub-ca-cert.pem", "r");
        if (!subCaBIO) {
			printf("ERROR: Cannot open Sub ca cert\n");
            success = false;
            goto err;
        }

        if (!PEM_read_bio_X509(subCaBIO, &subCaX509, NULL, NULL)) {
			printf("ERROR: Cannot parse Sub ca cert\n");
            success = false;
            goto err;
        }

        ca = sk_X509_new_null();
        if (!sk_X509_push(ca, subCaX509)) {
			printf("ERROR: Cannot add cert to store\n");
            success = false;
            goto err;
        }

        publicCertBIO = BIO_new_file(pPublicCertPath, "r");
        if (!publicCertBIO) {
			printf("ERROR: Cannot open public certificate path\n");
            success = false;
            goto err;
        }

        if (!PEM_read_bio_X509(publicCertBIO, &publicCert, NULL, NULL)) {
			printf("ERROR: Cannot parse public certificate\n");
            success = false;
            goto err;
        }

        privateKeyBIO = BIO_new_file(pPrivateKeyPath, "r");
        if (!privateKeyBIO) {
			printf("ERROR: Cannot open private key\n");
            success = false;
            goto err;
        }
        /*
         * Open PKCS8
         */
        PEM_read_bio_PKCS8(privateKeyBIO, &p8, 0, NULL);
        if (!p8) {
			printf("ERROR: Cannot read public key\n");
            success = false;
            goto err;
        }

        p8inf = PKCS8_decrypt(p8, pPassword, strlen(pPassword));
        if (!p8inf) {
			printf("ERROR: Cannot decrypt public key\n");
            success = false;
            goto err;
        }

        pKey = EVP_PKCS82PKEY(p8inf);
        if (!pKey) {
			printf("ERROR: Cannot get public key\n");
            success = false;
            goto err;
        }

        /*-------------------------------------------------------------------*/

        p7 = PKCS7_sign(publicCert, pKey, ca, inBIO, flags);
        if (!p7) {
			printf("ERROR: Cannot perform sign operation\n");
            success = false;
            goto err;
        }

        outBIO = BIO_new_file(pOutputPath, "w");
        if (!SMIME_write_PKCS7(outBIO, p7, inBIO, flags)) {
			printf("ERROR: Cannot write signed data\n");
            success = false;
            goto err;
        }

        err: if (!success) {
            error = ERR_error_string(ERR_get_error(), NULL);
			printf(error);
        }

        BIO_free(subCaBIO);
        BIO_free(inBIO);
        BIO_free(publicCertBIO);
        BIO_free(outBIO);
        BIO_free(privateKeyBIO);
        X509_free(subCaX509);
        X509_free(publicCert);
        EVP_PKEY_free(pKey);
        return success;
    }


    /*
     * Overloaded SMIME_sign function. The procedure is the same with one exception
     * it will not save the buffer in file system, but write the ouput in BIO * pOutBIO.
     * @param pData The plain text data to be signed.
     * @param pPassword The password to be used for decrypting the private key (PKCS8).
     * @param pPrivateKeyPath The file path of the private key (PKCS8).
     * @param pPublicCertPath The file path of the public certificate.
     * @param pOutBIO BIO where the signed multipart/mixed message will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_sign(const char * pData, const char * pPassword, const char * pPrivateKeyPath,
            const char * pPublicCertPath, BIO * pOutBIO)
    {
        OpenSSL_add_all_algorithms();
        int flags = PKCS7_BINARY | PKCS7_STREAM | PKCS7_NOCERTS; //
        bool success = true;
        BIO * inBIO = NULL;
        BIO * publicCertBIO = NULL;
        FILE * privateCertFILE = NULL;
        X509 * publicCert = NULL;
        X509 * privateCert = NULL;
        PKCS12 * p12 = NULL;
        EVP_PKEY * pKey = NULL;
        STACK_OF(X509) * ca = NULL;
        PKCS7 *p7 = NULL;
        int size = strlen(pData);
        std::vector<char> plain_text_data(pData, pData + size);

        inBIO = BIO_new(BIO_s_mem());
        std::vector<unsigned char> data = create_MIME(plain_text_data, crypto::attachmentList);
        if (data.empty()) {
            success = false;
            goto err;
        }

        BIO_write(inBIO, &data[0], data.size());
        if (!inBIO) {
            success = false;
            goto err;
        }

        publicCertBIO = BIO_new_file(pPublicCertPath, "r");
        if (!publicCertBIO) {
            success = false;
            goto err;
        }

        if (!PEM_read_bio_X509(publicCertBIO, &publicCert, NULL, NULL)) {
            success = false;
            goto err;
        }

        privateCertFILE = fopen(pPrivateKeyPath, "rb");
        if (!privateCertFILE) {
            success = false;
            goto err;
        }
        p12 = d2i_PKCS12_fp(privateCertFILE, NULL);
        if (!p12) {
            success = false;
            goto err;
        }
        fclose(privateCertFILE);

        PKCS12_parse(p12, pPassword, &pKey, &privateCert, &ca);
        if (!pKey || !privateCert) {
            success = false;
            goto err;
        }

        p7 = PKCS7_sign(publicCert, pKey, ca, inBIO, flags);
        if (!p7) {
            success = false;
            goto err;
        }

        if (!SMIME_write_PKCS7(pOutBIO, p7, inBIO, flags)) {
            success = false;
            goto err;
        }

        err: if (!success) {
            //Error message here
        }

        BIO_free(inBIO);
        BIO_free(publicCertBIO);
        X509_free(publicCert);
        X509_free(privateCert);
        EVP_PKEY_free(pKey);
        sk_X509_pop_free(ca, X509_free);
        PKCS12_free(p12);
        return success;
    }


    /*
     * Verifies a signature in a signed multipart/mixed message, removes the signature from buffer and saves it in char * pOutputPath.
     * The saved format is a simple multipart/mixed message.
     * @param pSignedDataPath The file path of the signed multipart/mixed message.
     * @param pOutputPath The file path where the signature-stripped buffer is saved.
     * @param pSubCaCertPath The Sub CA certificate file path, this is used for chain verification. (TODO: NOT CURRENTLY VERIFYING CA CHAIN)
     * @param pCaCertPath The Root CA certificate file path, this is used for chain verification. (TODO: NOT CURRENTLY VERIFYING CA CHAIN)
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_verify_signature(const char * pSignedDataPath, const char * pOutputPath,
            const char * pSubCaCertPath, const char * pCaCertPath)
    {
        char * error = NULL;
        BIO *out = NULL, *cont = NULL, *signedDataBIO = NULL, *CACertBIO = NULL, *subCACertBIO =
                NULL;
        X509_STORE *CACertStore = NULL;
        X509 * CACert = NULL;
        X509* subCACert = NULL;
        PKCS7 *p7 = NULL;
        int flags = PKCS7_BINARY | PKCS7_NOCHAIN | PKCS7_NOVERIFY; // | PKCS7_NOVERIFY | PKCS7_NOSIGS | PKCS7_NOINTERN |
        bool ret = true;
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* Set up trusted CA certificate store */

        CACertStore = X509_STORE_new();

        signedDataBIO = BIO_new_file(pSignedDataPath, "r");
        if (!signedDataBIO) {
			printf("ERROR: Failed to open signed data\n");
            ret = false;
            goto err;
        }
        CACertBIO = BIO_new_file(pCaCertPath, "r");
        if (!CACertBIO) {
			printf("ERROR: Failed to open CA certificate\n");
            ret = false;
            goto err;
        }

        subCACertBIO = BIO_new_file(pSubCaCertPath, "r");
        if (!subCACertBIO) {
			printf("ERROR: Failed to open CA certificate\n");
            ret = false;
            goto err;
        }

        if (!PEM_read_bio_X509(subCACertBIO, &subCACert, NULL, NULL)) {
			printf("ERROR: Failed to read sub ca certificate\n");
            ret = false;
            goto err;
        }
        if (!PEM_read_bio_X509(CACertBIO, &CACert, NULL, NULL)) {
			printf("ERROR: Failed to read ca certificate\n");
            ret = false;
            goto err;
        }

        if (!X509_STORE_add_cert(CACertStore, subCACert)) {
			printf("ERROR: Failed to add sub ca certificate to trusted store\n");
            ret = false;
            goto err;
        }
        if (!X509_STORE_add_cert(CACertStore, CACert)) {
			printf("ERROR: Failed to add ca certificate to trusted store\n");
            ret = false;
            goto err;
        }

        p7 = SMIME_read_PKCS7(signedDataBIO, &cont);
        if (!p7) {
			printf("ERROR: Failed parse PKCS7 structure\n");
            ret = false;
            goto err;
        }

        /* File to output verified content to */
        out = BIO_new_file(pOutputPath, "w");
        if (!out) {
			printf("ERROR: Failed to open output data file\n");
            ret = false;
            goto err;
        }

        if (!PKCS7_verify(p7, NULL, CACertStore, cont, out, flags)) {
			printf("ERROR: Signature is invalid\n");
            ret = false;
            goto err;
        }

        err: if (!ret) {
            error = ERR_error_string(ERR_get_error(), NULL);
			printf(error);
            fprintf(stderr, "Error Verifying Data\n");
            ERR_print_errors_fp(stderr);
        }
        PKCS7_free(p7);
        X509_free(CACert);
        X509_free(subCACert);
        BIO_free(signedDataBIO);
        BIO_free(out);
        BIO_free(cont);
        BIO_free(CACertBIO);
        BIO_free(subCACertBIO);

        return ret;
    }


    /*
     * Overloaded SMIME_verify_signature. The procedure is the same with one exception
     * it will not read the signed multipart/mixed message from file system, but will expect it from BIO * pDataToVerifyBIO.
     * @param pSignedDataPath The file path of the signed multipart/mixed message.
     * @param pOutputPath The file path where the signature-stripped buffer is saved.
     * @param pSubCaCertPath The Sub CA certificate file path, this is used for chain verification. (TODO: NOT CURRENTLY VERIFYING CA CHAIN)
     * @param pCaCertPath The Root CA certificate file path, this is used for chain verification. (TODO: NOT CURRENTLY VERIFYING CA CHAIN)
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_verify_signature(const char * pSignerCertificatePath, BIO * pDataToVerifyBIO,
            const char * pOutputPath, const char * pCaCertPath)
    {
        char * error = NULL;
        BIO *out = NULL, *cont = NULL, *publicCertBIO = NULL, *CACertBIO = NULL;
        X509_STORE *CACertStore = NULL;
        X509 *publicCert = NULL;
        X509 * CACert = NULL;
        STACK_OF(X509) *signers = NULL;
        PKCS7 *p7 = NULL;
        int flags = PKCS7_NOINTERN | PKCS7_BINARY; // | PKCS7_NOVERIFY | PKCS7_NOSIGS |
        bool ret = true;
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* Set up trusted CA certificate store */

        CACertStore = X509_STORE_new();

        /* Read in signer certificate */
        publicCertBIO = BIO_new_file(pSignerCertificatePath, "r");
        if (!publicCertBIO) {
            ret = false;
            goto err;
        }

        CACertBIO = BIO_new_file(pCaCertPath, "r");
        if (!CACertBIO) {
            ret = false;
            goto err;
        }
        if (!PEM_read_bio_X509(publicCertBIO, &publicCert, NULL, NULL)) {
            ret = false;
            goto err;
        }
        if (!PEM_read_bio_X509(CACertBIO, &CACert, NULL, NULL)) {
            ret = false;
            goto err;
        }

        if (!X509_STORE_add_cert(CACertStore, CACert)) {
            ret = false;
            goto err;
        }

        signers = sk_X509_new_null();
        if (!sk_X509_push(signers, publicCert)) {
            ret = false;
            goto err;
        }

        p7 = SMIME_read_PKCS7(pDataToVerifyBIO, NULL);
        if (!p7) {
            ret = false;
            goto err;
        }

        /* File to output verified content to */
        out = BIO_new_file(pOutputPath, "w");
        if (!out) {
            ret = false;
            goto err;
        }

        if (!PKCS7_verify(p7, signers, CACertStore, NULL, out, flags)) {
            ret = false;
            goto err;
        }

        err: if (!ret) {
            error = ERR_error_string(ERR_get_error(), NULL);
        }
        PKCS7_free(p7);
        X509_free(publicCert);
        BIO_free(publicCertBIO);
        BIO_free(out);
        BIO_free(cont);

        return ret;
    }


    /*
     * Encrypts buffer pDataToEncrypt and saves it into EncryptedDataOutputPath, it will encrypt it with both keys.
     * @param pDataToEncrypt The file path where the data to be encrypted is.
     * @param pSenderPublicCertPath The sender's public certificate.
     * @param pRecipientPublicCertPath The recipient's public certificate.
     * @param pEncryptedDataOutputPath The file path where the encrypted buffer will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_encrypt(const char * pDataToEncrypt, const char * pSenderPublicCertPath,
            const char * pRecipientPublicCertPath, const char * pEncryptedDataOutputPath)
    {
        char * error = NULL;
        BIO * dataToEncrypt = NULL;
        BIO * encryptedData = NULL;
        BIO * senderPublicCertBIO = NULL;
        BIO * recipientPublicCertBIO = NULL;
        STACK_OF(X509) *recipients = NULL;
        X509* x509 = NULL;
        PKCS7 * p7 = NULL;
        int flags = PKCS7_STREAM | PKCS7_BINARY;
        bool ret = false;

        dataToEncrypt = BIO_new_file(pDataToEncrypt, "r");
        if (!dataToEncrypt) {
            ret = false;
			printf("ERROR: Cannot open data to encrypt file\n");
            goto err;
        }

        recipientPublicCertBIO = BIO_new_file(pRecipientPublicCertPath, "r");
        if (!recipientPublicCertBIO) {
			printf("ERROR: Cannot open recipient public certificate file\n");
            ret = false;
            goto err;
        }

        if (!PEM_read_bio_X509(recipientPublicCertBIO, &x509, NULL, NULL)) {
			printf("ERROR: Cannot read recipient public certificate\n");
            ret = false;
            goto err;
        }

        recipients = sk_X509_new_null();
        if (!recipients || !sk_X509_push(recipients, x509)) {
			printf("ERROR: Cannot add recipient to stack of recipients\n");
            ret = false;
            goto err;
        }

        x509 = NULL;

        senderPublicCertBIO = BIO_new_file(pSenderPublicCertPath, "r");
        if (!senderPublicCertBIO) {
			printf("ERROR: Cannot open sender public certificate\n");
            ret = false;
            goto err;
        }

        if (!PEM_read_bio_X509(senderPublicCertBIO, &x509, NULL, NULL)) {
			printf("ERROR: Cannot read sender public certificate\n");
            ret = false;
            goto err;
        }

        if (!recipients || !sk_X509_push(recipients, x509)) {
			printf("ERROR: Cannot push sender to stack of recipients\n");
            ret = false;
            goto err;
        }

        p7 = PKCS7_encrypt(recipients, dataToEncrypt, EVP_aes_256_cbc(), flags);
        if (!p7) {
			printf("ERROR: Cannot perfom encryption\n");
            ret = false;
            goto err;
        }

        encryptedData = BIO_new_file(pEncryptedDataOutputPath, "w");
        if (!encryptedData) {
			printf("ERROR:Cannot open encrypted data output\n");
            ret = false;
            goto err;
        }

        if (!i2d_PKCS7_bio_stream(encryptedData, p7, dataToEncrypt, flags)) {
			printf("ERROR: Cannot flush encrypted data to file\n");
            ret = false;
            goto err;
        }
        ret = true;

        err: if (!ret) {
            error = ERR_error_string(ERR_get_error(), NULL);
			printf(error);
        }
        BIO_free(encryptedData);
        X509_free(x509);
        BIO_free(dataToEncrypt);
        PKCS7_free(p7);
//		 sk_X509_pop_free(recipients, X509_free);
        BIO_free(recipientPublicCertBIO);
        BIO_free(senderPublicCertBIO);
        return ret;
    }


    /*
     * Overloaded SMIME_encrypt function, the procedure is the same with one exception,
     * it will expect the data to be encrypted from pDataToEncrypt.
     * @param pDataToEncrypt The data to be encrypted in a BIO.
     * @param pSenderPublicCertPath The sender's public certificate.
     * @param pRecipientPublicCertPath The recipient's public certificate.
     * @param pEncryptedDataOutputPath The file path where the encrypted buffer will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_encrypt(BIO * pDataToEncrypt, const char * pSenderPublicCertPath,
            const char * pRecipientPublicCertPath, const char * pEncryptedDataOutputPath)
    {
        BIO * encryptedData = NULL;
        BIO * senderPublicCertBIO = NULL;
        BIO * recipientPublicCertBIO = NULL;
        STACK_OF(X509) *recipients = NULL;
        X509* x509 = NULL;
        PKCS7 * p7 = NULL;
        int flags = PKCS7_STREAM | PKCS7_BINARY;
        bool ret = false;

        recipientPublicCertBIO = BIO_new_file(pRecipientPublicCertPath, "r");
        if (!recipientPublicCertBIO) {
            ret = false;
            goto err;
        }

        if (!PEM_read_bio_X509(recipientPublicCertBIO, &x509, NULL, NULL)) {
            ret = false;
            goto err;
        }

        recipients = sk_X509_new_null();
        if (!recipients || !sk_X509_push(recipients, x509)) {
            ret = false;
            goto err;
        }

        x509 = NULL;

        senderPublicCertBIO = BIO_new_file(pSenderPublicCertPath, "r");
        if (!senderPublicCertBIO) {
            ret = false;
            goto err;
        }

        if (!PEM_read_bio_X509(senderPublicCertBIO, &x509, NULL, NULL)) {
            ret = false;
            goto err;
        }

        if (!recipients || !sk_X509_push(recipients, x509)) {
            ret = false;
            goto err;
        }

        x509 = NULL;

        p7 = PKCS7_encrypt(recipients, pDataToEncrypt, EVP_aes_256_cbc(), flags);
        if (!p7) {
            ret = false;
            goto err;
        }

        encryptedData = BIO_new_file(pEncryptedDataOutputPath, "w");
        if (!encryptedData) {
            ret = false;
            goto err;
        }

        if (!i2d_PKCS7_bio_stream(encryptedData, p7, pDataToEncrypt, flags)) {
            ret = false;
            goto err;
        }
        ret = true;

        err: if (!ret) {
            std::cout << "ERROR: Exiting encryption function" << std::endl;
        }

        BIO_free(encryptedData);
        X509_free(x509);
        PKCS7_free(p7);
        sk_X509_pop_free(recipients, X509_free);
        BIO_free(recipientPublicCertBIO);
        BIO_free(senderPublicCertBIO);
        return ret;
    }


    /*
     * Decrypts SMIME data and saves the decrypted data in a file.
     * @param pPrivateKeyPath The file path of the private key.
     * @param pPassword The password to decrypt the private key.
     * @param pPublicCertPath The file path of the public certificate.
     * @param pEncryptedDataPath The file path where the encrypted data will be loaded.
     * @param pDecryptedDataOutputPath The file path where the decrypted data will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool SMIME_decrypt(const char * pPrivateKeyPath, const char * pPassword,
            const char * pPublicCertPath, const char * pEncryptedDataPath,
            const char * pDecryptedDataOutputPath)
    {
        char * error = NULL;
        PKCS12 * p12 = NULL;
        EVP_PKEY * pKey = NULL;
        X509 * cert = NULL;
        BIO * privateKeyBIO = NULL;
        BIO * publicCertBIO = NULL;
        bool ret = true;
        PKCS7 * p7 = NULL;
        BIO * out = NULL;
        FILE * encryptedDataFILE = NULL;
        X509_SIG * p8 = NULL;
        PKCS8_PRIV_KEY_INFO * p8inf = NULL;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        publicCertBIO = BIO_new_file(pPublicCertPath, "r");
        if (!publicCertBIO) {
			printf("ERROR: Cannot open public cert\n");
            ret = false;
            goto err;
        }

        if (!PEM_read_bio_X509(publicCertBIO, &cert, NULL, NULL)) {
			printf("ERROR: Cannot parse public cert\n");
            ret = false;
            goto err;
        }

        privateKeyBIO = BIO_new_file(pPrivateKeyPath, "r");
        if (!privateKeyBIO) {
			printf("ERROR: Cannot open private key\n");
            ret = false;
            goto err;
        }
        /*
         * Open PKCS8
         */
        PEM_read_bio_PKCS8(privateKeyBIO, &p8, 0, NULL);
        if (!p8) {
			printf("ERROR: Cannot read public key\n");
            ret = false;
            goto err;
        }

        p8inf = PKCS8_decrypt(p8, pPassword, strlen(pPassword));
        if (!p8inf) {
			printf("ERROR: Cannot decrypt public key\n");
            ret = false;
            goto err;
        }

        pKey = EVP_PKCS82PKEY(p8inf);
        if (!pKey) {
			printf("ERROR: Cannot get public key\n");
            ret = false;
            goto err;
        }

        encryptedDataFILE = fopen(pEncryptedDataPath, "r");
        if (!encryptedDataFILE) {
            ret = false;
            goto err;
        }

        p7 = d2i_PKCS7_fp(encryptedDataFILE, NULL);

        if (!p7) {
            ret = false;
            goto err;
        }

        fclose(encryptedDataFILE);

        out = BIO_new_file(pDecryptedDataOutputPath, "w");
        if (!out) {
            ret = false;
            goto err;
        }

        if (!PKCS7_decrypt(p7, pKey, cert, out, 0)) {
            ret = false;
            goto err;
        }

        err: if (!ret) {
            error = ERR_error_string(ERR_get_error(), NULL);
			printf(error);
        }

        BIO_free(publicCertBIO);
        BIO_free(privateKeyBIO);
        BIO_free(out);
        PKCS12_free(p12);
        X509_free(cert);
        EVP_PKEY_free(pKey);
        PKCS7_free(p7);
        return ret;
    }

    /*
     * Overloaded SMIME_decrypt, the procedure is the same with one exception,
     * the decrypted data will be returned in a BIO *.
     * @param pPrivateKeyPath The file path of the private key.
     * @param pPassword The password to decrypt the private key.
     * @param pPublicCertPath The file path of the public certificate.
     * @param pEncryptedDataPath The file path where the encrypted data will be loaded.
     * @param pDecryptedDataOutputPath The file path where the decrypted data will be saved.
     * @return BIO * containing the data
     */
    BIO * SMIME_decrypt(const char * pPrivateKeyPath, const char * pPassword,
            const char * pEncryptedDataPath)
    {
        PKCS12 * p12 = NULL;
        EVP_PKEY * pkey = NULL;
        STACK_OF(X509) * ca = NULL;
        X509 * cert = NULL;
        FILE * certFILE = NULL;
        bool ret = false;
        PKCS7 * p7 = NULL;
        FILE * encryptedDataFILE = NULL;
        BIO * decryptedDataBIO = NULL;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        //OPEN PKCS12 FILE
        if (!(certFILE = fopen(pPrivateKeyPath, "rb"))) {
            ret = false;
            goto err;
        }

        p12 = d2i_PKCS12_fp(certFILE, NULL);
        fclose(certFILE);
        if (!p12) {
            ret = false;
            goto err;
        }

        // PARSE PKCS12 FILE CONTENT
        if (!PKCS12_parse(p12, pPassword, &pkey, &cert, &ca)) {
            ret = false;
            goto err;
        }

        encryptedDataFILE = fopen(pEncryptedDataPath, "r");
        if (!encryptedDataFILE) {
            ret = false;
            goto err;
        }

        p7 = d2i_PKCS7_fp(encryptedDataFILE, NULL);

        if (!p7) {
            ret = false;
            goto err;
        }

        fclose(encryptedDataFILE);
        decryptedDataBIO = BIO_new(BIO_s_mem());
        if (!PKCS7_decrypt(p7, pkey, cert, decryptedDataBIO, 0)) {
            ret = false;
            goto err;
        }

        ret = true;

        err: if (!ret) {
        }

        PKCS12_free(p12);
        sk_X509_pop_free(ca, X509_free);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(p7);
        return decryptedDataBIO;
    }

    /*
     * Password Key Derivation Function 2 (PBKDF2) with SHA 512 , takes in a sequence of char and outputs a brute force resistant hash.
     * Uses SHA512 as the hashing algorithm.
     * @param pPassword The user supplied char sequence that will be hashed.
     * @param pSalt The salt to add uniqueness to the hash result.
     * @param pSaltLen The length of the salt.
     * @param pNumIterations The number of hashing iterations, more iterations means harder security and more time to validate.
     * @param pOutputBytes The expected hash output size in bytes.
     * @param pHashResult The hash result of the operation.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool PBKDF2_HMAC_SHA_512_string(const char* pPassword, const unsigned char * pSalt, int pSaltLen, int pNumIterations, int pOutputBytes, unsigned char* pHashResult)
    {
        if (PKCS5_PBKDF2_HMAC(pPassword, strlen(pPassword), pSalt, pSaltLen, pNumIterations, EVP_sha512(),
                pOutputBytes, pHashResult) == false) {
			printf("ERROR: PBKDF2 cannot hash password, aborting.\n");
            return false;
        }
        return true;
    }

    /*
     * Pseudo random number generator, generates random bytes.
     * @param pBuf Where the output bytes will be stored.
     * @param pBufSize The desired size of the buffer in bytes.
     * @return Will return True if the operation succeeded and False otherwise.
     */
    bool generate_PRN(unsigned char * pBuf, int pBufSize)
    {
		printf("INFO: Generating PRN.\n");
        return RAND_bytes(pBuf, pBufSize);
    }

    /*
     * AES CBC encryption implementation
     * @param plaintext The buffer to be encrypted.
     * @param plaintext_len Buffer's length.
     * @param key Symmetric key.
     * @param key_len Symmetric key length.
     * @param iv Initialization vector
     * @param cipertext Output ciphertext
     * @return Ciphertext length if encryption was succesful, returns 0 otherwise.
     */
    int AES_CBC_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char *key, int key_len,
            unsigned char *iv, unsigned char* ciphertext)
    {
        bool errorHappened = false;
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len = 0;
        int iv_size_evp = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        int key_size_evp = EVP_CIPHER_key_length(EVP_aes_256_cbc());

        /*Check that the key and iv sizes are correct, or it could yeld undesirable results */
        if (key_len != key_size_evp) {
			printf("ERROR: KEY size must be: %d \n", iv_size_evp);
			printf("ERROR: Passed KEY size is: %d \n ", sizeof(key));
            errorHappened = true;
            goto err;
        }
        if (Constants::SYMMETRIC_ENCRIPTION_IV_LENGTH != iv_size_evp) {
			printf("ERROR: IV size must be: %d \n", key_size_evp);
			printf("ERROR: Passed IV size is: %d \n",  sizeof(iv));
            errorHappened = true;
            goto err;
        }

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
			printf("ERROR: Failed to initialize the context\n");
            errorHappened = true;
            goto err;
        }

        /* Initialise the encryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
			printf("ERROR: Failed the enryption operation\n");
            errorHappened = true;
            goto err;
        }

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
			printf("ERROR: Cannot execute encryption operation\n");
            errorHappened = true;
            goto err;
        }
        ciphertext_len = len;

        /* Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
			printf("ERROR: Cannot finalize the encryption operation\n");
            errorHappened = true;
            goto err;
        }
        ciphertext_len += len;

        err: if (errorHappened) {
			printf("ERROR: Something wrong happened with symmetric encryption\n");
            ciphertext_len = 0;
        }

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    }

    /*
     * AES CBC decryption implementation
     * @param ciphertext The encrypted data to decrypt.
     * @param ciphertext_len The encrypted data length.
     * @param key Symmetric key to decrypt with.
     * @param iv The initialization vector
     * @param plaintext The decrypted plaintext
     * @return Plaintext size if decryption was succesful, returns 0 otherwise.
     */
    int AES_CBC_decrypt(unsigned char * ciphertext, int ciphertext_len, unsigned char * key, unsigned char * iv, unsigned char * plaintext)
    {
        bool hasErrors = false;
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
			printf("ERROR: Cannot initialize decryption context\n");
            hasErrors = true;
            goto err;
        }

        /* Initialise the decryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
			printf("ERROR: Cannot initialize decryption operation\n");
            hasErrors = true;
            goto err;
        }

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
			printf("ERROR: Cannot execute decryption operation\n");
            hasErrors = true;
            goto err;
        }
        plaintext_len = len;

        /* Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
			printf("ERROR: Cannot get plaintext from decryption context\n");
            hasErrors = true;
            goto err;
        }
        plaintext_len += len;

        err: if (hasErrors) {
			printf("ERROR: There was an error with the decryption operation, aborting.\n");
            plaintext_len = 0;
        }

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
    }

    /*
     * AES GCM 256 encryption implementation.
     *  Requirements:
     * - Key must be 32 Bytes long
     * - Auth tag must be 16 Bytes long
     *
     * @param plaintext The buffer to be encrypted.
     * @param key The symmetric key.
     * @param iv The initialization vector.
     * @param auth_tag Authentication tag, for integrity verification.
     * @return Ciphertext result of the encryption operation
     * TODO: Error handling
     */
    std::vector<unsigned char> AES_GCM_encrypt(std::vector<unsigned char> plaintext,
            std::vector<unsigned char> key, std::vector<unsigned char> iv, unsigned char * auth_tag)
    {
        int iv_len = iv.size();
        //Set cipher type
        const EVP_CIPHER *cipher_type = EVP_aes_256_gcm();
        int key_len = key.size();
        if (key_len != 32) {
			printf("ERROR: GCM key length is not 32\n");
        }

        // Make a buffer for the ciphertext that is the same size as the
        // plaintext, but padded to key size increments
        int plaintext_len = plaintext.size();
        int ciphertext_len = (((plaintext_len - 1) / key_len) + 1) * key_len;
		printf("Calculated ciphertext length: %d \n", ciphertext_len);
        unsigned char *ciphertext = new unsigned char[ciphertext_len];

        // Create the OpenSSL context
        int outl;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // Init the OpenSSL interface with the selected AES GCM cipher
        EVP_EncryptInit_ex(ctx, cipher_type, NULL, NULL, NULL);
        // Set the IV length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
        // Init OpenSSL interace with the key and IV
        EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *) &key[0], (unsigned char *) &iv[0]);
        //Encrypt plaintext
        EVP_EncryptUpdate(ctx, ciphertext, &outl, (unsigned char *) &plaintext[0], plaintext_len);
        ciphertext_len = outl;

        // Finalize
        EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl);
        ciphertext_len += outl;
        // Get the authentication tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag);
        // Free the OpenSSL interface structure
        EVP_CIPHER_CTX_free(ctx);

        return std::vector<unsigned char>(ciphertext, ciphertext + ciphertext_len);
    }


    /*
     * AES GCM 256 decryption implementation.
     *  Requirements:
     * - Key must be 32 Bytes long
     * - Auth tag must be 16 Bytes long
     *
     * @param ciphertext The buffer to be encrypted.
     * @param key The symmetric key.
     * @param iv The initialization vector.
     * @param tag Authentication tag, for integrity verification.
     * @return Plaintext result of the encryption operation
     * TODO: Error handling
     */
    std::vector<unsigned char> AES_GCM_decrypt(std::vector<unsigned char> ciphertext,
            std::vector<unsigned char> key, std::vector<unsigned char> iv,
            std::vector<unsigned char> tag, bool * success)
    {
        const EVP_CIPHER *cipher_type = EVP_aes_256_gcm();
        int key_len = 32;

        // Make a buffer for the plaintext that is the same size as the
        // ciphertext, but padded to key size increments
        int ciphertext_len = ciphertext.size();
        int plaintext_len = ciphertext_len; // ??
        //unsigned char *plaintext = new unsigned char[plaintext_len];
        unsigned char * plaintext = (unsigned char *) malloc(sizeof(unsigned char) * plaintext_len);
        // Create the OpenSSL context
        int outl;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // Init the OpenSSL interface with the selected AES GCM cipher
        EVP_DecryptInit_ex(ctx, cipher_type, NULL, NULL, NULL);
        // Set the IV length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
        // Init OpenSSL interface with the key and IV
        EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char *) &key[0], (unsigned char *) &iv[0]);

        //Decrypt ciphertext
        EVP_DecryptUpdate(ctx, plaintext, &outl, (unsigned char *) &ciphertext[0],
                ciphertext.size());
        // Set the input reference authentication tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *) &tag[0]);
        // Finalize
        *success = EVP_DecryptFinal_ex(ctx, plaintext + outl, &outl);
        // Free the OpenSSL interface structure
        EVP_CIPHER_CTX_free(ctx);
        if (*success) {
			printf("INFO: Authentication tag verified successfully\n");
            return std::vector<unsigned char>(plaintext, plaintext + plaintext_len);
        } else {
			printf("ERROR: Authentication tag mismatch\n");
            return std::vector<unsigned char>();
        }

    }

    std::vector<unsigned char> AES_GCM_decrypt(std::vector<unsigned char> ciphertext,
            std::vector<unsigned char> key, std::vector<unsigned char> iv,
            unsigned char * tag, bool * success)
    {
        const EVP_CIPHER *cipher_type = EVP_aes_256_gcm();
        int key_len = 32;

        // Make a buffer for the plaintext that is the same size as the
        // ciphertext, but padded to key size increments
        int ciphertext_len = ciphertext.size();
        int plaintext_len = ciphertext_len; // ??
        //unsigned char *plaintext = new unsigned char[plaintext_len];
        unsigned char * plaintext = (unsigned char *) malloc(sizeof(unsigned char) * plaintext_len);
        // Create the OpenSSL context
        int outl;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // Init the OpenSSL interface with the selected AES GCM cipher
        EVP_DecryptInit_ex(ctx, cipher_type, NULL, NULL, NULL);
        // Set the IV length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
        // Init OpenSSL interface with the key and IV
        EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char *) &key[0], (unsigned char *) &iv[0]);

        // Decrypt ciphertext
        EVP_DecryptUpdate(ctx, plaintext, &outl, (unsigned char *) &ciphertext[0],
                ciphertext.size());
        // Set the input reference authentication tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        // Finalize
        *success = EVP_DecryptFinal_ex(ctx, plaintext + outl, &outl);
        // Free the OpenSSL interface structure
        EVP_CIPHER_CTX_free(ctx);
        if (*success) {
			printf("INFO: Authentication tag verified successfully\n");
            return std::vector<unsigned char>(plaintext, plaintext + plaintext_len);
        } else {
			printf( "ERROR: Authentication tag mismatch\n");
            return std::vector<unsigned char>();
        }

    }

}

