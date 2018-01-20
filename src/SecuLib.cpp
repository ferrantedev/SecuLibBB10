#include <stdio.h>
#include <stdlib.h>
#include <MimeParser.hpp>
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

using namespace mime;

void test_prng() {
	printf("TESTCASE: Testing PRNG.\n");
	int saltSize = 8;
	unsigned char * salt = (unsigned char *)malloc(sizeof(unsigned char) * saltSize);
	bool result = crypto::generate_PRN(salt, saltSize);
	assert(result == true);
	free(salt);
	printf("TESTRESULT: PRNG generated successfully.\n");
}

void generate_pkcs1()
{
	printf("TESTCASE: Generating PKCS1.\n");
	char * password = "supersecurepassword";
	bool generation_success = crypto::generate_PKCS1(Constants::PRIVATE_KEY_BASE_PATH,
		Constants::PULIC_KEY_BASE_PATH, password, 4096);
	assert(generation_success == true);
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
		Constants::PRIVATE_KEY_BASE_PATH);
	assert(open_success == true);
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
	bool generation_success = crypto::generate_PKCS10(Constants::PRIVATE_KEY_BASE_PATH,
		Constants::PULIC_KEY_BASE_PATH, Constants::CSR_PATH, &holderInfo,
		password);
	assert(generation_success);
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
	if (!DirExists("C:\\Users\\sigterm\\Documents\\testdata")) {
		CreateFolder("C:\\Users\\sigterm\\Documents\\testdata");
	}
	if (!DirExists("C:\\Users\\sigterm\\Documents\\testdata\\certs")) {
		CreateFolder("C:\\Users\\sigterm\\Documents\\testdata\\certs");
	}
}

int main(int argc, char *argv[])
{
	setup_folders();
	test_prng();
	generate_pkcs1();
	try_open_pkcs8();
	generate_pks10();
	const char * data;
	const char * password;
	BIO * signedBIO = BIO_new(BIO_s_mem());
	bool ok = crypto::SMIME_sign(data, password, Constants::PRIVATE_KEY_BASE_PATH, Constants::PUBLIC_CERTIFICATE_PATH, signedBIO);
	if (ok == false) {
		printf("TESTRESULT: SMIME_SIGN failed\n");
		return 0;
	}
	BIO * encryptedBIO = BIO_new(BIO_s_mem());
	ok = crypto::SMIME_encrypt(signedBIO, Constants::PUBLIC_CERTIFICATE_PATH, Constants::PUBLIC_CERTIFICATE_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\public-cert.pem", Constants::TEMP_ENCRYPTED_DATA_OUTPATH);
	if (ok == false) {
		printf("TESTRESULT: SMIME_ENCRYPT failed\n");
		return 0;
	}

	return 0;
}
