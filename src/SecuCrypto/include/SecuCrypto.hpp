/* Copyright (C) Secucom, Inc - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by j11, September 2016
*/

#ifndef SECUCRYPTO_HPP_
#define SECUCRYPTO_HPP_

#include <openssl/bio.h>

#ifdef __QNX__ || __LINUX__
    #include <unistd.h>
    #include <string.h>
#endif

#include <string>
#include <iostream>
#include <vector>

namespace crypto
{
    extern std::vector<std::string> attachmentList;
    struct CSR_Requred_Fields
    {
        char * country; // eg.IT
        char * province; // eg.RM
        char * city; // eg.Rome
        char * org; // eg.Secucom
        char * ou;
        unsigned char * common;
    };

    /*
     * PKCS1 generation function, basically will output an RSA key pair.
     * @param pPrivateKeyPath the path where the private key will be saved.
     * @param pPublicKeyPath the path where the public key will be saved.
     * @param pPassword the password for the private key, (PKCS8)
     * @return Will return True if generation succeeded and False otherwise.
     */
    bool generate_PKCS1(const char * pPrivateKeyPath, const char * pPublicKeyPath, char * pPassword,
            const int pBitSize);

    /*
    * Attempts to decrypt an encrypted private key (PKCS8), this is used to verify that the password is correct.
    * @param pPassword The password that will be used to decrypt the key.
    * @param pPrivateKeyPath The file path of the PKCS8 file.
    * @return Will return True if decryption succeeded (password correct) and False otherwise (password incorrect).
    */
    bool try_open_PKCS8(const char* pPassword, const char * pPrivateKeyPath);

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
            const char * pCSRSavePath, const CSR_Requred_Fields * pInfo, const char * pPassword);

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
            const char * publicCertPath, const char * pOutputPath);

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
            const char * pPublicCertPath, BIO * pOutBIO);

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
            const char * pSubCaCertPath, const char * pCaCertPath);

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
            const char * pOutputPath, const char * pCaCertPath);

    /*
     * Encrypts buffer pDataToEncrypt and saves it into EncryptedDataOutputPath, it will encrypt it with both keys.
     * @param pDataToEncrypt The file path where the data to be encrypted is.
     * @param pSenderPublicCertPath The sender's public certificate.
     * @param pRecipientPublicCertPath The recipient's public certificate.
     * @param pEncryptedDataOutputPath The file path where the encrypted buffer will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
    */
    bool SMIME_encrypt(BIO * pDataToEncrypt, const char * pSenderPublicCertPath,
            const char * pRecipientPublicCertPath, const char * pEncryptedDataOutputPath);

    /*
     * Overloaded SMIME_encrypt function, the procedure is the same with one exception,
     * it will expect the data to be encrypted from pDataToEncrypt.
     * @param pDataToEncrypt The data to be encrypted in a BIO.
     * @param pSenderPublicCertPath The sender's public certificate.
     * @param pRecipientPublicCertPath The recipient's public certificate.
     * @param pEncryptedDataOutputPath The file path where the encrypted buffer will be saved.
     * @return Will return True if the operation succeeded and False otherwise.
    */
    bool SMIME_encrypt(const char * pDataToEncrypt, const char * pSenderPublicCertPath,
            const char * pRecipientPublicCertPath, const char * pEncryptedDataOutputPath);
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
            const char * pDecryptedDataOutputPath);

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
            const char * pEncryptedDataPath);

    /*
     * Password Key Derivation Function 2 (PBKDF2), takes in a sequence of char and outputs a brute force resistant hash.
     * Uses SHA512 as the hashing algorithm.
     * @param pPassword The user supplied char sequence that will be hashed.
     * @param pSalt The salt to add uniqueness to the hash result.
     * @param pSaltLen The length of the salt.
     * @param pNumIterations The number of hashing iterations, more iterations means harder security and more time to validate.
     * @param pOutputBytes The expected hash output size in bytes.
     * @param pHashResult The hash result of the operation.
     * @return Will return True if the operation succeeded and False otherwise.
    */
    bool PBKDF2_HMAC_SHA_512_string(const char* pPassword, const unsigned char * pSalt, int pSaltLen, int pNumIterations, int pOutputBytes, unsigned char* pHashResult);

    /*
     * Pseudo random number generator, generates random bytes.
     * @param pBuf Where the output bytes will be stored.
     * @param pBufSize The desired size of the buffer in bytes.
     * @return Will return True if the operation succeeded and False otherwise.
    */
    bool generate_PRN(unsigned char* pBuf, int pBufSize);

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
    int AES_CBC_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char* ciphertext);


    /*
     * AES CBC decryption implementation
     * @param ciphertext The encrypted data to decrypt.
     * @param ciphertext_len The encrypted data length.
     * @param key Symmetric key to decrypt with.
     * @param iv The initialization vector
     * @param plaintext The decrypted plaintext
     * @return Plaintext size if decryption was succesful, returns 0 otherwise.
     */
    int AES_CBC_decrypt(unsigned char * ciphertext, int ciphertext_len, unsigned char * key, unsigned char * iv, unsigned char * plaintext);

    /*
     * Checks if buffer a equals buffer b
     * @param a Buffer a
     * @param b Buffer b
     * @return True if they are equal, false otherwise.
     */
    bool equals(unsigned char *a, unsigned char *b, int size);


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
            std::vector<unsigned char> key, std::vector<unsigned char> iv,
            unsigned char * auth_tag);


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
            std::vector<unsigned char> tag, bool* success);

    std::vector<unsigned char> AES_GCM_decrypt(std::vector<unsigned char> ciphertext,
                std::vector<unsigned char> key, std::vector<unsigned char> iv,
                unsigned char * tag, bool * success);

}


#endif /* SECUCRYPTO_HPP_ */
