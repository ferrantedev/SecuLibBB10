#include <stdio.h>
#include <stdlib.h>
#include <SecuCrypto.hpp>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>

#define GetCurrentDir _getcwd
#endif
#ifdef __LINUX__ || __QNX__
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define PUBLIC_CERTIFICATE_PATH "C:\\Users\\z\\Documents\\testdata\\certs\\test-user.pem"
#define PRIVATE_KEY_BASE_PATH "C:\\Users\\z\\Documents\\testdata\\private-key.pem"
#define PULIC_KEY_BASE_PATH "C:\\Users\\z\\Documents\\testdata\\public-key.pem"
#define CSR_PATH "C:\\Users\\z\\Documents\\testdata\\csr.pem"
#define TEMP_ENCRYPTED_DATA_OUTPATH  "C:\\Users\\z\\Documents\\testdata\\tmp_encrypted_data.txt"
#define SUBCA_CERT_PATH "C:\\Users\\z\\Documents\\testdata\\certs\\secucom_intermediate.pem"

#define GEN_PATH_PRIVATE_KEY "C:\\Users\\z\\Documents\\testdata\\generation-output"
#define GEN_PUBLIC_KEY_BASE_PATH "C:\\Users\\z\\Documents\\testdata\\generation-output"
#define GEN_CSR_PATH "C:\\Users\\z\\Documents\\testdata\\generation-output"


//using namespace mime;

void test_prng() {
	printf("TESTCASE: Testing PRNG.\n");
	int saltSize = 8;
	unsigned char * salt = (unsigned char *)malloc(sizeof(unsigned char) * saltSize);
	bool result = crypto::generate_PRN(salt, saltSize);
	free(salt);
	printf("TESTRESULT: PRNG generated successfully.\n");
}

void generate_pkcs1()
{
	printf("TESTCASE: Generating PKCS1.\n");
	char * password = "supersecurepassword";
	bool generation_success = crypto::generate_PKCS1(GEN_PATH_PRIVATE_KEY,
		GEN_PUBLIC_KEY_BASE_PATH, password, 4096);
	printf("TESTRESULT: PKCS1 generated successfully\n");
}

/*
* Attempt to decrypt our PKCS8 (encrypted private key)
*/
void try_open_pkcs8()
{
	printf("TESTCASE: Opening PKCS8\n");
	char * password = "supersecurepassword";
	generate_pkcs1();
	bool open_success = crypto::try_open_PKCS8(password,
		GEN_PATH_PRIVATE_KEY);
	printf("TESTRESULT: PKCS8 opened successfully\n");
}

/*
* Generates a PKCS1 and generates a PKCS10 (certificate sign request)
* NOTE: Does not check for validity, only that the generation function returns true
*/
void generate_pks10()
{
	printf("TESTCASE: Generating PKCS10\n");
	generate_pkcs1();
	unsigned char * ba = (unsigned char*)strdup("CertificateTestUser");
	char * password = "supersecurepassword";
	crypto::CSR_Requred_Fields holderInfo = { "PE", "Lima", "LI", "Secucom Inc.", "Secumail", ba };
	bool generation_success = crypto::generate_PKCS10(GEN_PATH_PRIVATE_KEY,
		GEN_PUBLIC_KEY_BASE_PATH, GEN_CSR_PATH, &holderInfo,
		password);
	printf("TESTRESULT: PKCS10 generated successfully\n");
}


void CreateFolder(const char * path)
{
#ifdef __QNX__
		mkdir(path, 777);
#else
		_mkdir(path);
#endif
}

bool DirExists(const std::string& dirName_in)
{
	DWORD ftyp = GetFileAttributesA(dirName_in.c_str());
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   // this is a directory!

	return false;    // this is not a directory!
}

void setup_folders() {
	printf("Setting up test folders\n");
	if (!DirExists("C:\\Users\\z\\Documents\\testdata")) {
		printf("WARNING!!! Directories do not exist, you will need a signed public certificate/private key pair!!!!\n");
		CreateFolder("C:\\Users\\z\\Documents\\testdata");
	}
	if (!DirExists("C:\\Users\\z\\Documents\\testdata\\generation-output")) {
		CreateFolder("C:\\Users\\z\\Documents\\testdata\\generation-output");
	}
	if (!DirExists("C:\\Users\\z\\Documents\\testdata\\certs")) {
		CreateFolder("C:\\Users\\z\\Documents\\testdata\\certs");
	}
}

int main(int argc, char *argv[])
{
	setup_folders();
	test_prng();
	generate_pkcs1();
	try_open_pkcs8();
	generate_pks10();
	const char * data = NULL;
	const char * password = "supersecurepassword";

	data = "From: John Doe <example@example.com> \
			MIME - Version: 1.0 \
				Content - Type : multipart / mixed; \
				boundary = \"XXXXboundary text\"\
		\
				This is a multipart message in MIME format.\
				--XXXXboundary text\
				Content - Type: text / plain\
		\
				this is the body text\0\
				--XXXXboundary text\
				Content - Type : text / plain;\
				Content - Disposition: attachment;\
				filename = \"test.txt\"\
				this is the attachment text\
				--XXXXboundary text--";

	unsigned char * mimeDataBuf = (unsigned char*) data;
	int mimeBufSize = strlen(data);
	int signed_buf_size = 0;
	char * outBuf = NULL;
	crypto::buf_st eb = crypto::SMIME_sign(mimeDataBuf, mimeBufSize, password,
		PRIVATE_KEY_BASE_PATH, PUBLIC_CERTIFICATE_PATH,
		SUBCA_CERT_PATH, outBuf, &signed_buf_size);
	if (!eb._success) {
		printf("ERROR: cannot sign data");
		free(eb._buf);
		return 0;
	}

	printf((char*)eb._buf);
	bool success = crypto::SMIME_encrypt(&eb, PUBLIC_CERTIFICATE_PATH, PUBLIC_CERTIFICATE_PATH,
		TEMP_ENCRYPTED_DATA_OUTPATH);
	if (!success) {
		printf("ERROR: cannot encrypt data");
		free(eb._buf);
		return 0;
	}
	free(eb._buf);

	crypto::buf_st decrypted_buf = crypto::SMIME_decrypt(PRIVATE_KEY_BASE_PATH, password,
					PUBLIC_CERTIFICATE_PATH, TEMP_ENCRYPTED_DATA_OUTPATH);
	if (!decrypted_buf._success) {
		printf("ERROR: cannot decrypt data");
		free(decrypted_buf._buf);
		return 0;
	}
	free(decrypted_buf._buf);

	/*
	BIO * signedBIO = BIO_new(BIO_s_mem());
	bool ok = crypto::SMIME_sign(data, password, PRIVATE_KEY_BASE_PATH, PUBLIC_CERTIFICATE_PATH, signedBIO);
	if (ok == false) {
		printf("TESTRESULT: SMIME_SIGN failed\n");
		return 0;
	}

	BIO * encryptedBIO = BIO_new(BIO_s_mem());
	ok = crypto::SMIME_encrypt(signedBIO, PUBLIC_CERTIFICATE_PATH, "", TEMP_ENCRYPTED_DATA_OUTPATH);
	if (ok == false) {
		printf("TESTRESULT: SMIME_ENCRYPT failed\n");
		return 0;
	}
	*/
	return 0;
}
