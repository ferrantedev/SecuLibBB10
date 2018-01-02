/* Copyright (C) Secucom, Inc - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* @author by sigterm, September 2016
*/

#include "MimeParser.hpp"
#include <openssl/rand.h>

namespace mime {
	typedef unsigned char BYTE;
	std::vector<std::string> receivedAttachmentList;

	std::vector<unsigned char> create_MIME(std::vector<char> pData, std::vector<std::string> attachment_list) {
		std::streampos size;
		char * memblock = NULL;
		char * output = NULL;
		char * multipart = "MIME-Version: 1.0 \nContent - Type: multipart / mixed;";
		char * boundary_start = "boundary=\"";
		char uuidv4[38];
		int rc = uuid_v4_gen(uuidv4);
		char * new_line = "\n\n";
		char * boundary_end = "\"\n\n This is a multipart message in MIME format.\n\n";
		char * content_type_text = "Content-Type: text/plain;\n\n";
		char * trails = "--";
		//Create the multipart message header
		std::vector<unsigned char> mime_header(multipart, multipart + strlen(multipart));
		mime_header.insert(mime_header.end(), boundary_start, boundary_start + strlen(boundary_start));
		mime_header.insert(mime_header.end(), &uuidv4[0], &uuidv4[38]);
		mime_header.insert(mime_header.end(), boundary_end, boundary_end + strlen(boundary_end));

		//Create the boundary
		std::vector<unsigned char> boundary(trails, trails + strlen(trails));
		boundary.insert(boundary.end(), &uuidv4[0], &uuidv4[38]);

		//Build the message
		std::vector<unsigned char> mime_message(mime_header.begin(), mime_header.end());
		mime_message.insert(mime_message.end(), boundary.begin(), boundary.end());
		mime_message.insert(mime_message.end(), new_line, new_line + strlen(new_line));

		mime_message.insert(mime_message.end(), content_type_text, content_type_text + strlen(content_type_text));
		mime_message.insert(mime_message.end(), pData.begin(), pData.end());
		mime_message.insert(mime_message.end(), new_line, new_line + strlen(new_line));
		mime_message.insert(mime_message.end(), boundary.begin(), boundary.end());
		mime_message.insert(mime_message.end(), new_line, new_line + strlen(new_line));

		if (attachment_list.size() > 0) {
			for (int i = 0; i < attachment_list.size(); i++) {
				printf("INFO: Adding attachment number %d \n",  i);
				printf("INFO: Attachment path from MIME %d \n", attachment_list.at(i).data());
				std::ifstream file(attachment_list.at(i).data(), std::ios::in | std::ios::binary | std::ios::ate);
				std::vector<char> format = find_format(&attachment_list.at(i));
				if (format.empty()) {
					return mime_message;
				}
				mime_message.insert(mime_message.end(), format.begin(), format.end());
				mime_message.insert(mime_message.end(), new_line, new_line + strlen(new_line));
				if (file.is_open())
				{
					size = file.tellg();
					memblock = new char[size];
					file.seekg(0, std::ios::beg);
					file.read(memblock, size);
					file.close();
					//TODO: insert content type
					mime_message.insert(mime_message.end(), &memblock[0], &memblock[size]);
					mime_message.insert(mime_message.end(), new_line, new_line + strlen(new_line));
					mime_message.insert(mime_message.end(), boundary.begin(), boundary.end());
					mime_message.insert(mime_message.end(), new_line, new_line + strlen(new_line));

					delete[] memblock;
				}
				else {
					printf("ERROR: Cannot open attachment file \n");
				}
			}
		}
		return mime_message;
	}

	std::vector<char> find_format(std::string * pFilepath) {
		int size = pFilepath->length();
		std::string trim = pFilepath->substr(size - 5, size);
		std::vector<char> format;
		size_t total_types = sizeof(Constants::FILE_EXTENSIONS) / sizeof(Constants::FILE_EXTENSIONS[0]);
		for (unsigned int i = 0; i <= total_types; i++) {
			if (trim.find(Constants::FILE_EXTENSIONS[i]) != std::string::npos) {
				const char * found_format = Constants::CONTENT_TYPES[i].data();
				const char * filename_format_begin = " filename=\"";
				const char * end_quote = "\"";
				std::size_t index_of_backslash = pFilepath->find_last_of("//");
				std::string name = pFilepath->substr(index_of_backslash + 1);
				//TODO: remove format end because it corrupts output file after mime decomposition
				format.insert(format.end(), found_format, found_format + strlen(found_format));
				format.insert(format.end(), filename_format_begin, filename_format_begin + strlen(filename_format_begin));
				format.insert(format.end(), name.c_str(), name.c_str() + strlen(name.c_str()));
				format.insert(format.end(), end_quote, end_quote + strlen(end_quote));

				break;
			}
		}
		return format;
	}

	std::string find_simple_format(std::string pFilepath) {
		int totalSize = pFilepath.length();
		size_t lastDot = pFilepath.find_last_of(".");
		std::string trim = pFilepath.substr(lastDot, totalSize);
		size_t total_types = sizeof(Constants::FILE_EXTENSIONS) / sizeof(Constants::FILE_EXTENSIONS[0]);
		for (unsigned int i = 0; i <= total_types; i++) {
			if (trim.find(Constants::FILE_EXTENSIONS[i]) != std::string::npos) {
				if (Constants::FILE_EXTENSIONS[i] == trim) {
					//qDebug() << Constants::FILE_EXTENSIONS[i].c_str() << endl;
					return Constants::CONTENT_TYPES[i].data();
				}
			}

		}
		return "error";
	}


	void write_buffer_to_file(const char *pFilepath, unsigned char * pBuffer, size_t pFileLength) {
		FILE *fd = fopen(pFilepath, "wb");
		if (fd == NULL) {
			printf("ERROR: Cannot write buffer to file\n");
			exit(1);
		}

		size_t bytesWritten = fwrite(pBuffer, 1, pFileLength, fd);

		if (bytesWritten != pFileLength) {
			printf("ERROR: Failed writing file\n");
			exit(1);
		}

		fclose(fd);
	}
	/** @brief Generate a Version 4 UUID according to RFC-4122
	*
	* Uses the openssl RAND_bytes function to generate a
	* Version 4 UUID.
	*
	* @param buffer A buffer that is at least 38 bytes long.
	* @retval 1 on success, 0 otherwise.
	*/
	int uuid_v4_gen(char *pBuffer)
	{
		union
		{
			struct
			{
				uint32_t time_low;
				uint16_t time_mid;
				uint16_t time_hi_and_version;
				uint8_t  clk_seq_hi_res;
				uint8_t  clk_seq_low;
				uint8_t  node[6];
			};
			uint8_t __rnd[16];
		} uuid;

		int rc = RAND_bytes(uuid.__rnd, sizeof(uuid));

		// Refer Section 4.2 of RFC-4122
		// https://tools.ietf.org/html/rfc4122#section-4.2
		uuid.clk_seq_hi_res = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
		uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

		snprintf(pBuffer, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
			uuid.clk_seq_hi_res, uuid.clk_seq_low,
			uuid.node[0], uuid.node[1], uuid.node[2],
			uuid.node[3], uuid.node[4], uuid.node[5]);

		return rc;
	}	

	bool parse_multipart_content(const char * pFileToLoad, const char * pSavePath, const unsigned char * pData) {
		printf("INFO: Opening attachment, load path: %s \n", pFileToLoad);
		printf("INFO: Attachments save path: %s \n", pSavePath);

		//std::string attachmentSavePath = baseSavePath.substr(0, index_of_backslash + 1);

		std::string attachmentSavePath(pSavePath);

		std::string plain_text;
		//Load attachment to buffer
		std::vector<BYTE> buf = load_attachment(pFileToLoad);
		bool hasMoreBoundaries = true;

		std::vector<BYTE> boundary = parse_boundary(buf);
		if (boundary.empty()) {
			printf("ERROR: Cannot parse boundary in passed buffer");
			return false;
		}

		while (hasMoreBoundaries) {
			std::vector<BYTE>::iterator first_boundary = std::search(buf.begin(), buf.end(), boundary.begin(), boundary.end());
			size_t first_b_pos = first_boundary - buf.begin();
			if (first_boundary == buf.end()) {
				hasMoreBoundaries = false;
				break;
			}
		
			std::vector<BYTE>::iterator second_boundary = std::search(first_boundary + 38, buf.end(), boundary.begin(), boundary.end());
			size_t second_b_pos = second_boundary - buf.begin();
			//If our second boundary is at the end of the message,			
			//means we are at the end of the message and we break out of the loop.
			if (second_boundary == buf.end()) {
				hasMoreBoundaries = false;
				break;
			}
			//Trim content within the boundaries
			std::vector<BYTE> content(&buf[first_b_pos + 42], &buf[second_b_pos + 1]);
			//Get the header (Content-Type: text/plain) that is inside
			std::vector<BYTE> header = get_content_header(content);
			//Get the attachment extension of the content (imag/jpeg)
			std::string file_extension = identify_extension(header);
			//Get the attachment name
			std::string file_name = get_attachment_name(header);
			//Get the content body to be written to a file
			std::vector<BYTE> content_body = erase_header_from_content(content, header);
			//Write the content to a file the file_name+file_extension

			if (file_name.size() > 0) {
				save_attachment_to_fs(attachmentSavePath, content_body, file_name);
				receivedAttachmentList.push_back(attachmentSavePath + file_name);
			}
			else {
				pData = content_body.data();
			}
			//Erase the content we have parsed
			buf.erase(first_boundary, second_boundary);
		}

		return false;
	}

	std::vector<BYTE> load_attachment(const char * pFilepath) {
		std::ifstream file(pFilepath, std::ios::binary);
		printf("INFO: Loading file");
		std::vector<BYTE> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		file.close();
		printf("INFO: Done loading file");
		return buffer;
	}

	std::vector<BYTE> parse_boundary(std::vector<BYTE> & pBuffer) {
		const BYTE* boundary_hit_pattern = reinterpret_cast<const BYTE *>("=\"");
		const BYTE* dash = reinterpret_cast<const BYTE *>("-");

		std::vector<BYTE>::iterator begin_boundary = std::find(pBuffer.begin(), pBuffer.end(), *boundary_hit_pattern);
		if (begin_boundary == pBuffer.end()) {
			std::vector<BYTE> no_boundary;
			return no_boundary;
		}

		std::vector<BYTE>::iterator end_boundary = begin_boundary + 38;
		std::vector<BYTE> boundary(begin_boundary, end_boundary);
		std::replace(boundary.begin(), boundary.end(), boundary_hit_pattern[0], *dash);
		std::replace(boundary.begin(), boundary.end(), boundary_hit_pattern[1], *dash);
		return boundary;
	}

	std::string identify_extension(std::vector<BYTE> & pHeader) {
		std::string file_extension;
		for (int i = 0; i <= Constants::CONTENT_TYPES->size(); i++) {
			std::string header(pHeader.begin(), pHeader.end());
			if (header.find(Constants::CONTENT_TYPES[i]) != std::string::npos) {
				file_extension = Constants::FILE_EXTENSIONS[i];
				break;
			}
		}
		return file_extension;
	}

	std::string get_attachment_name(std::vector<BYTE> & pHeader) {
		std::string name;
		std::string filename_start_delimiter = "filename=\"";
		std::string filename_end_delimiter = "\"";
		std::string header(pHeader.begin(), pHeader.end());
		printf("INFO: MIME header %s \n", header.c_str());
		size_t delimiter_size = filename_start_delimiter.size();
		size_t first = header.find(filename_start_delimiter);
		if (first == std::string::npos) {
			return name;
		}
		size_t last = header.find_last_of(filename_end_delimiter);
		name = header.substr(first + delimiter_size, last);
		//Quick hack to get rid of a trailing " at the end of the name
		return name.substr(0, name.size() - 1);
	}

	std::vector<BYTE> erase_header_from_content(std::vector<BYTE> & pContent, std::vector<BYTE> & pHeader) {
		size_t size = pHeader.end() - pHeader.begin() + 2;
		std::vector<BYTE> content_body(&pContent[size], &pContent[(pContent.end() - pContent.begin() - 1)]);
		return content_body;
	}

	std::vector<BYTE> get_content_header(std::vector<BYTE> & pContent) {
		const BYTE * newline = reinterpret_cast<const BYTE *>("\n");
		std::vector<BYTE> header(pContent.begin(), std::find(pContent.begin(), pContent.end(), *newline));
		return header;
	}

	void save_attachment_to_fs(std::string pSavePath, std::vector<BYTE> & pContent_body, std::string pFile_name) {
		std::string path = pSavePath + pFile_name;
		std::ofstream output_file(path.data(), std::ios::out | std::ofstream::binary);
		std::copy(pContent_body.begin(), pContent_body.end(), std::ostreambuf_iterator<char>(output_file));
		output_file.close();
	}

	const int Constants::AUTH_MODE_MASTER_ONLY = 0;
	const int Constants::AUTH_MODE_ALL_PASSWORDS = 1;
	const int Constants::AES_GCM_KEY_BYTE_SIZE = 32;
	const int Constants::AES_GCM_AUTH_TAG_BYTE_SIZE = 16;
	const int Constants::AES_GCM_IV_BYTE_SIZE = 16;
	const char * Constants::TEMP_ENCRYPTED_DATA_OUTPATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\encrypted_data.file";
	const int Constants::SYMMETRIC_PASSWORD_ITERATION_COUNT = 50000;
	const int Constants::SYMMETRIC_ENCRIPTION_IV_LENGTH = 16;
	const char * Constants::PRIVATE_KEY_BASE_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\private-key.pem";
	const char * Constants::PULIC_KEY_BASE_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\public-key.pem";
	const char * Constants::CSR_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\principal\\csr.pem";
	const char * Constants::PUBLIC_CERTIFICATE_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\public-cert.pem";
	const char * Constants::PRIVATE_CERTIFICATE_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs\\private-cert.pem";
	const char * Constants::SQLITE_CONNECTION = "secumail_db";
	const char * Constants::DATABASE_FILE = "data/secumail.db";
	const char * Constants::PKI_URL = "http://192.168.0.15";
	const char * Constants::PKI_POST_CSR_PATH = "/csr";
	const char * Constants::PKI_CHECK_CSR_STATUS_PATH = "/csr/status";
	const char * Constants::PKI_CHECK_RECIPIENT_PATH = "/subject";
	const char * Constants::CA_CERT_PATH = "C:\\Users\\sigterm\\Documents\\testdata\\certs//root-ca-cert.pem";//"/data/certificates/ca/cacert.pem";
	const char * Constants::RECIPIENTS_BASE_PATH = "data/certificates/recipients/";
	const char * Constants::SUB_CA_CERT_PATH = "app/native/assets/certs/sub-ca-cert.pem";
	const char * Constants::PASSWORD_KEEPER_PATH = "data/keeper.psk";

	const std::string Constants::FILE_EXTENSIONS[] = { ".3dm",
		".3dmf",
		".a",
		".aab",
		".aam",
		".aas",
		".abc",
		".acgi",
		".afl",
		".ai",
		".aif",
		".aif",
		".aifc",
		".aifc",
		".aiff",
		".aiff",
		".aim",
		".aip",
		".ani",
		".aos",
		".aps",
		".arc",
		".arj",
		".arj",
		".art",
		".asf",
		".asm",
		".asp",
		".asx",
		".asx",
		".asx",
		".au",
		".au",
		".avi",
		".avi",
		".avi",
		".avi",
		".avs",
		".bcpio",
		".bin",
		".bin",
		".bin",
		".bin",
		".bin",
		".bm",
		".bmp",
		".bmp",
		".boo",
		".book",
		".boz",
		".bsh",
		".bz",
		".bz2",
		".c",
		".c",
		".c++",
		".cat",
		".cc",
		".cc",
		".ccad",
		".cco",
		".cdf",
		".cdf",
		".cdf",
		".cer",
		".cer",
		".cha",
		".chat",
		".class",
		".class",
		".class",
		".com",
		".com",
		".conf",
		".cpio",
		".cpp",
		".cpt",
		".cpt",
		".cpt",
		".crl",
		".crl",
		".crt",
		".crt",
		".crt",
		".csh",
		".csh",
		".css",
		".css",
		".cxx",
		".dcr",
		".deepv",
		".def",
		".der",
		".dif",
		".dir",
		".dl",
		".dl",
		".doc",
		".docx",
		".dot",
		".dp",
		".drw",
		".dump",
		".dv",
		".dvi",
		".dwf",
		".dwf",
		".dwg",
		".dwg",
		".dwg",
		".dxf",
		".dxf",
		".dxf",
		".dxr",
		".el",
		".elc",
		".elc",
		".env",
		".eps",
		".es",
		".etx",
		".evy",
		".evy",
		".exe",
		".f",
		".f",
		".f77",
		".f90",
		".f90",
		".fdf",
		".fif",
		".fif",
		".fli",
		".fli",
		".flo",
		".flx",
		".fmf",
		".for",
		".for",
		".fpx",
		".fpx",
		".frl",
		".funk",
		".g",
		".g3",
		".gif",
		".gl",
		".gl",
		".gsd",
		".gsm",
		".gsp",
		".gss",
		".gtar",
		".gz",
		".gz",
		".gzip",
		".gzip",
		".h",
		".h",
		".hdf",
		".help",
		".hgl",
		".hh",
		".hh",
		".hlb",
		".hlp",
		".hlp",
		".hlp",
		".hpg",
		".hpgl",
		".hqx",
		".hqx",
		".hqx",
		".hqx",
		".hqx",
		".hqx",
		".hta",
		".htc",
		".htm",
		".html",
		".htmls",
		".htt",
		".htx",
		".ice",
		".ico",
		".idc",
		".ief",
		".iefs",
		".iges",
		".iges",
		".igs",
		".igs",
		".ima",
		".imap",
		".inf",
		".ins",
		".ip",
		".isu",
		".it",
		".iv",
		".ivr",
		".ivy",
		".jam",
		".jav",
		".jav",
		".java",
		".java",
		".jcm",
		".jfif",
		".jfif",
		".jfif-tbnl",
		".jpe",
		".jpe",
		".jpeg",
		".jpeg",
		".jpg",
		".jpg",
		".jps",
		".js",
		".js",
		".js",
		".js",
		".js",
		".jut",
		".kar",
		".kar",
		".ksh",
		".ksh",
		".la",
		".la",
		".lam",
		".latex",
		".lha",
		".lha",
		".lha",
		".lhx",
		".list",
		".lma",
		".lma",
		".log",
		".lsp",
		".lsp",
		".lst",
		".lsx",
		".ltx",
		".lzh",
		".lzh",
		".lzx",
		".lzx",
		".lzx",
		".m",
		".m",
		".m1v",
		".m2a",
		".m2v",
		".m3u",
		".man",
		".map",
		".mar",
		".mbd",
		".mc$",
		".mcd",
		".mcd",
		".mcf",
		".mcf",
		".mcp",
		".me",
		".mht",
		".mhtml",
		".mid",
		".mid",
		".mid",
		".mid",
		".mid",
		".mid",
		".midi",
		".midi",
		".midi",
		".midi",
		".midi",
		".midi",
		".mif",
		".mif",
		".mime",
		".mime",
		".mjf",
		".mjpg",
		".mm",
		".mm",
		".mme",
		".mod",
		".mod",
		".moov",
		".mov",
		".movie",
		".mp2",
		".mp2",
		".mp2",
		".mp2",
		".mp2",
		".mp3",
		".mp3",
		".mp3",
		".mp3",
		".mpa",
		".mpa",
		".mpc",
		".mpe",
		".mpeg",
		".mpg",
		".mpg",
		".mpga",
		".mpp",
		".mpt",
		".mpv",
		".mpx",
		".mrc",
		".ms",
		".mv",
		".my",
		".mzz",
		".nap",
		".naplps",
		".nc",
		".ncm",
		".nif",
		".niff",
		".nix",
		".nsc",
		".nvd",
		".o",
		".oda",
		".omc",
		".omcd",
		".omcr",
		".p",
		".p10",
		".p10",
		".p12",
		".p12",
		".p7a",
		".p7c",
		".p7c",
		".p7m",
		".p7m",
		".p7r",
		".p7s",
		".part",
		".pas",
		".pbm",
		".pcl",
		".pcl",
		".pct",
		".pcx",
		".pdb",
		".pdf",
		".pfunk",
		".pfunk",
		".pgm",
		".pgm",
		".pic",
		".pict",
		".pkg",
		".pko",
		".pl",
		".pl",
		".plx",
		".pm",
		".pm",
		".pm4",
		".pm5",
		".png",
		".pnm",
		".pnm",
		".pot",
		".pot",
		".pov",
		".ppa",
		".ppm",
		".pps",
		".pps",
		".ppt",
		".ppt",
		".ppt",
		".ppt",
		".ppz",
		".pre",
		".prt",
		".ps",
		".psd",
		".pvu",
		".pwz",
		".py",
		".pyc",
		".qcp",
		".qd3",
		".qd3d",
		".qif",
		".qt",
		".qtc",
		".qti",
		".qtif",
		".ra",
		".ra",
		".ra",
		".ram",
		".ras",
		".ras",
		".ras",
		".rast",
		".rexx",
		".rf",
		".rgb",
		".rm",
		".rm",
		".rmi",
		".rmm",
		".rmp",
		".rmp",
		".rng",
		".rng",
		".rnx",
		".roff",
		".rp",
		".rpm",
		".rt",
		".rt",
		".rtf",
		".rtf",
		".rtf",
		".rtx",
		".rtx",
		".rv",
		".s",
		".s3m",
		".saveme",
		".sbk",
		".scm",
		".scm",
		".scm",
		".scm",
		".sdml",
		".sdp",
		".sdp",
		".sdr",
		".sea",
		".sea",
		".set",
		".sgm",
		".sgm",
		".sgml",
		".sgml",
		".sh",
		".sh",
		".sh",
		".sh",
		".shar",
		".shar",
		".shtml",
		".shtml",
		".sid",
		".sit",
		".sit",
		".skd",
		".skm",
		".skp",
		".skt",
		".sl",
		".smi",
		".smil",
		".snd",
		".snd",
		".sol",
		".spc",
		".spc",
		".spl",
		".spr",
		".sprite",
		".src",
		".ssi",
		".ssm",
		".sst",
		".step",
		".stl",
		".stl",
		".stl",
		".stp",
		".sv4cpio",
		".sv4crc",
		".svf",
		".svf",
		".svr",
		".svr",
		".swf",
		".t",
		".talk",
		".tar",
		".tbk",
		".tbk",
		".tcl",
		".tcl",
		".tcsh",
		".tex",
		".texi",
		".texinfo",
		".text",
		".text",
		".tgz",
		".tgz",
		".tif",
		".tif",
		".tiff",
		".tiff",
		".tr",
		".tsi",
		".tsp",
		".tsp",
		".tsv",
		".turbot",
		".txt",
		".uil",
		".uni",
		".unis",
		".unv",
		".uri",
		".uris",
		".ustar",
		".ustar",
		".uu",
		".uu",
		".uue",
		".vcd",
		".vcs",
		".vda",
		".vdo",
		".vew",
		".viv",
		".viv",
		".vivo",
		".vivo",
		".vmd",
		".vmf",
		".voc",
		".voc",
		".vos",
		".vox",
		".vqe",
		".vqf",
		".vql",
		".vrml",
		".vrml",
		".vrml",
		".vrt",
		".vsd",
		".vst",
		".vsw",
		".w60",
		".w61",
		".w6w",
		".wav",
		".wav",
		".wb1",
		".wbmp",
		".web",
		".wiz",
		".wk1",
		".wmf",
		".wml",
		".wmlc",
		".wmls",
		".wmlsc",
		".word",
		".wp",
		".wp5",
		".wp5",
		".wp6",
		".wpd",
		".wpd",
		".wq1",
		".wri",
		".wri",
		".wrl",
		".wrl",
		".wrl",
		".wrz",
		".wrz",
		".wsc",
		".wsrc",
		".wtk",
		".xbm",
		".xbm",
		".xbm",
		".xdr",
		".xgz",
		".xif",
		".xl",
		".xla",
		".xla",
		".xla",
		".xlb",
		".xlb",
		".xlb",
		".xlc",
		".xlc",
		".xlc",
		".xld",
		".xld",
		".xlk",
		".xlk",
		".xll",
		".xll",
		".xll",
		".xlm",
		".xlm",
		".xlm",
		".xls",
		".xls",
		".xls",
		".xls",
		".xlt",
		".xlt",
		".xlv",
		".xlv",
		".xlw",
		".xlw",
		".xlw",
		".xlw",
		".xm",
		".xml",
		".xml",
		".xmz",
		".xpix",
		".xpm",
		".xpm",
		".x-png",
		".xsr",
		".xwd",
		".xwd",
		".xyz",
		".z",
		".z",
		".zip",
		".zip",
		".zip",
		".zip",
		".zoo",
		".zsh",
		".mp4",
		".m4a" };
	const std::string Constants::CONTENT_TYPES[] = { "x-world/x-3dmf",
		"x-world/x-3dmf",
		"application/octet-stream",
		"application/x-authorware-bin",
		"application/x-authorware-map",
		"application/x-authorware-seg",
		"text/vnd.abc",
		"text/html",
		"video/animaflex",
		"application/postscript",
		"audio/aiff",
		"audio/x-aiff",
		"audio/aiff",
		"audio/x-aiff",
		"audio/aiff",
		"audio/x-aiff",
		"application/x-aim",
		"text/x-audiosoft-intra",
		"application/x-navi-animation",
		"application/x-nokia-9000-communicator-add-on-software",
		"application/mime",
		"application/octet-stream",
		"application/arj",
		"application/octet-stream",
		"image/x-jg",
		"video/x-ms-asf",
		"text/x-asm",
		"text/asp",
		"application/x-mplayer2",
		"video/x-ms-asf",
		"video/x-ms-asf-plugin",
		"audio/basic",
		"audio/x-au",
		"application/x-troff-msvideo",
		"video/avi",
		"video/msvideo",
		"video/x-msvideo",
		"video/avs-video",
		"application/x-bcpio",
		"application/mac-binary",
		"application/macbinary",
		"application/octet-stream",
		"application/x-binary",
		"application/x-macbinary",
		"image/bmp",
		"image/bmp",
		"image/x-windows-bmp",
		"application/book",
		"application/book",
		"application/x-bzip2",
		"application/x-bsh",
		"application/x-bzip",
		"application/x-bzip2",
		"text/plain",
		"text/x-c",
		"text/plain",
		"application/vnd.ms-pki.seccat",
		"text/plain",
		"text/x-c",
		"application/clariscad",
		"application/x-cocoa",
		"application/cdf",
		"application/x-cdf",
		"application/x-netcdf",
		"application/pkix-cert",
		"application/x-x509-ca-cert",
		"application/x-chat",
		"application/x-chat",
		"application/java",
		"application/java-byte-code",
		"application/x-java-class",
		"application/octet-stream",
		"text/plain",
		"text/plain",
		"application/x-cpio",
		"text/x-c",
		"application/mac-compactpro",
		"application/x-compactpro",
		"application/x-cpt",
		"application/pkcs-crl",
		"application/pkix-crl",
		"application/pkix-cert",
		"application/x-x509-ca-cert",
		"application/x-x509-user-cert",
		"application/x-csh",
		"text/x-script.csh",
		"application/x-pointplus",
		"text/css",
		"text/plain",
		"application/x-director",
		"application/x-deepv",
		"text/plain",
		"application/x-x509-ca-cert",
		"video/x-dv",
		"application/x-director",
		"video/dl",
		"video/x-dl",
		"application/msword",
		"application/msword",
		"application/msword",
		"application/commonground",
		"application/drafting",
		"application/octet-stream",
		"video/x-dv",
		"application/x-dvi",
		"drawing/x-dwf (old)",
		"model/vnd.dwf",
		"application/acad",
		"image/vnd.dwg",
		"image/x-dwg",
		"application/dxf",
		"image/vnd.dwg",
		"image/x-dwg",
		"application/x-director",
		"text/x-script.elisp",
		"application/x-bytecode.elisp (compiled elisp)",
		"application/x-elc",
		"application/x-envoy",
		"application/postscript",
		"application/x-esrehber",
		"text/x-setext",
		"application/envoy",
		"application/x-envoy",
		"application/octet-stream",
		"text/plain",
		"text/x-fortran",
		"text/x-fortran",
		"text/plain",
		"text/x-fortran",
		"application/vnd.fdf",
		"application/fractals",
		"image/fif",
		"video/fli",
		"video/x-fli",
		"image/florian",
		"text/vnd.fmi.flexstor",
		"video/x-atomic3d-feature",
		"text/plain",
		"text/x-fortran",
		"image/vnd.fpx",
		"image/vnd.net-fpx",
		"application/freeloader",
		"audio/make",
		"text/plain",
		"image/g3fax",
		"image/gif",
		"video/gl",
		"video/x-gl",
		"audio/x-gsm",
		"audio/x-gsm",
		"application/x-gsp",
		"application/x-gss",
		"application/x-gtar",
		"application/x-compressed",
		"application/x-gzip",
		"application/x-gzip",
		"multipart/x-gzip",
		"text/plain",
		"text/x-h",
		"application/x-hdf",
		"application/x-helpfile",
		"application/vnd.hp-hpgl",
		"text/plain",
		"text/x-h",
		"text/x-script",
		"application/hlp",
		"application/x-helpfile",
		"application/x-winhelp",
		"application/vnd.hp-hpgl",
		"application/vnd.hp-hpgl",
		"application/binhex",
		"application/binhex4",
		"application/mac-binhex",
		"application/mac-binhex40",
		"application/x-binhex40",
		"application/x-mac-binhex40",
		"application/hta",
		"text/x-component",
		"text/html",
		"text/html",
		"text/html",
		"text/webviewhtml",
		"text/html",
		"x-conference/x-cooltalk",
		"image/x-icon",
		"text/plain",
		"image/ief",
		"image/ief",
		"application/iges",
		"model/iges",
		"application/iges",
		"model/iges",
		"application/x-ima",
		"application/x-httpd-imap",
		"application/inf",
		"application/x-internett-signup",
		"application/x-ip2",
		"video/x-isvideo",
		"audio/it",
		"application/x-inventor",
		"i-world/i-vrml",
		"application/x-livescreen",
		"audio/x-jam",
		"text/plain",
		"text/x-java-source",
		"text/plain",
		"text/x-java-source",
		"application/x-java-commerce",
		"image/jpeg",
		"image/pjpeg",
		"image/jpeg",
		"image/jpeg",
		"image/pjpeg",
		"image/jpeg",
		"image/pjpeg",
		"image/jpeg",
		"image/pjpeg",
		"image/x-jps",
		"application/x-javascript",
		"application/javascript",
		"application/ecmascript",
		"text/javascript",
		"text/ecmascript",
		"image/jutvision",
		"audio/midi",
		"music/x-karaoke",
		"application/x-ksh",
		"text/x-script.ksh",
		"audio/nspaudio",
		"audio/x-nspaudio",
		"audio/x-liveaudio",
		"application/x-latex",
		"application/lha",
		"application/octet-stream",
		"application/x-lha",
		"application/octet-stream",
		"text/plain",
		"audio/nspaudio",
		"audio/x-nspaudio",
		"text/plain",
		"application/x-lisp",
		"text/x-script.lisp",
		"text/plain",
		"text/x-la-asf",
		"application/x-latex",
		"application/octet-stream",
		"application/x-lzh",
		"application/lzx",
		"application/octet-stream",
		"application/x-lzx",
		"text/plain",
		"text/x-m",
		"video/mpeg",
		"audio/mpeg",
		"video/mpeg",
		"audio/x-mpequrl",
		"application/x-troff-man",
		"application/x-navimap",
		"text/plain",
		"application/mbedlet",
		"application/x-magic-cap-package-1.0",
		"application/mcad",
		"application/x-mathcad",
		"image/vasa",
		"text/mcf",
		"application/netmc",
		"application/x-troff-me",
		"message/rfc822",
		"message/rfc822",
		"application/x-midi",
		"audio/midi",
		"audio/x-mid",
		"audio/x-midi",
		"music/crescendo",
		"x-music/x-midi",
		"application/x-midi",
		"audio/midi",
		"audio/x-mid",
		"audio/x-midi",
		"music/crescendo",
		"x-music/x-midi",
		"application/x-frame",
		"application/x-mif",
		"message/rfc822",
		"www/mime",
		"audio/x-vnd.audioexplosion.mjuicemediafile",
		"video/x-motion-jpeg",
		"application/base64",
		"application/x-meme",
		"application/base64",
		"audio/mod",
		"audio/x-mod",
		"video/quicktime",
		"video/quicktime",
		"video/x-sgi-movie",
		"audio/mpeg",
		"audio/x-mpeg",
		"video/mpeg",
		"video/x-mpeg",
		"video/x-mpeq2a",
		"audio/mpeg3",
		"audio/x-mpeg-3",
		"video/mpeg",
		"video/x-mpeg",
		"audio/mpeg",
		"video/mpeg",
		"application/x-project",
		"video/mpeg",
		"video/mpeg",
		"audio/mpeg",
		"video/mpeg",
		"audio/mpeg",
		"application/vnd.ms-project",
		"application/x-project",
		"application/x-project",
		"application/x-project",
		"application/marc",
		"application/x-troff-ms",
		"video/x-sgi-movie",
		"audio/make",
		"application/x-vnd.audioexplosion.mzz",
		"image/naplps",
		"image/naplps",
		"application/x-netcdf",
		"application/vnd.nokia.configuration-message",
		"image/x-niff",
		"image/x-niff",
		"application/x-mix-transfer",
		"application/x-conference",
		"application/x-navidoc",
		"application/octet-stream",
		"application/oda",
		"application/x-omc",
		"application/x-omcdatamaker",
		"application/x-omcregerator",
		"text/x-pascal",
		"application/pkcs10",
		"application/x-pkcs10",
		"application/pkcs-12",
		"application/x-pkcs12",
		"application/x-pkcs7-signature",
		"application/pkcs7-mime",
		"application/x-pkcs7-mime",
		"application/pkcs7-mime",
		"application/x-pkcs7-mime",
		"application/x-pkcs7-certreqresp",
		"application/pkcs7-signature",
		"application/pro_eng",
		"text/pascal",
		"image/x-portable-bitmap",
		"application/vnd.hp-pcl",
		"application/x-pcl",
		"image/x-pict",
		"image/x-pcx",
		"chemical/x-pdb",
		"application/pdf",
		"audio/make",
		"audio/make.my.funk",
		"image/x-portable-graymap",
		"image/x-portable-greymap",
		"image/pict",
		"image/pict",
		"application/x-newton-compatible-pkg",
		"application/vnd.ms-pki.pko",
		"text/plain",
		"text/x-script.perl",
		"application/x-pixclscript",
		"image/x-xpixmap",
		"text/x-script.perl-module",
		"application/x-pagemaker",
		"application/x-pagemaker",
		"image/png",
		"application/x-portable-anymap",
		"image/x-portable-anymap",
		"application/mspowerpoint",
		"application/vnd.ms-powerpoint",
		"model/x-pov",
		"application/vnd.ms-powerpoint",
		"image/x-portable-pixmap",
		"application/mspowerpoint",
		"application/vnd.ms-powerpoint",
		"application/mspowerpoint",
		"application/powerpoint",
		"application/vnd.ms-powerpoint",
		"application/x-mspowerpoint",
		"application/mspowerpoint",
		"application/x-freelance",
		"application/pro_eng",
		"application/postscript",
		"application/octet-stream",
		"paleovu/x-pv",
		"application/vnd.ms-powerpoint",
		"text/x-script.phyton",
		"application/x-bytecode.python",
		"audio/vnd.qcelp",
		"x-world/x-3dmf",
		"x-world/x-3dmf",
		"image/x-quicktime",
		"video/quicktime",
		"video/x-qtc",
		"image/x-quicktime",
		"image/x-quicktime",
		"audio/x-pn-realaudio",
		"audio/x-pn-realaudio-plugin",
		"audio/x-realaudio",
		"audio/x-pn-realaudio",
		"application/x-cmu-raster",
		"image/cmu-raster",
		"image/x-cmu-raster",
		"image/cmu-raster",
		"text/x-script.rexx",
		"image/vnd.rn-realflash",
		"image/x-rgb",
		"application/vnd.rn-realmedia",
		"audio/x-pn-realaudio",
		"audio/mid",
		"audio/x-pn-realaudio",
		"audio/x-pn-realaudio",
		"audio/x-pn-realaudio-plugin",
		"application/ringing-tones",
		"application/vnd.nokia.ringing-tone",
		"application/vnd.rn-realplayer",
		"application/x-troff",
		"image/vnd.rn-realpix",
		"audio/x-pn-realaudio-plugin",
		"text/richtext",
		"text/vnd.rn-realtext",
		"application/rtf",
		"application/x-rtf",
		"text/richtext",
		"application/rtf",
		"text/richtext",
		"video/vnd.rn-realvideo",
		"text/x-asm",
		"audio/s3m",
		"application/octet-stream",
		"application/x-tbook",
		"application/x-lotusscreencam",
		"text/x-script.guile",
		"text/x-script.scheme",
		"video/x-scm",
		"text/plain",
		"application/sdp",
		"application/x-sdp",
		"application/sounder",
		"application/sea",
		"application/x-sea",
		"application/set",
		"text/sgml",
		"text/x-sgml",
		"text/sgml",
		"text/x-sgml",
		"application/x-bsh",
		"application/x-sh",
		"application/x-shar",
		"text/x-script.sh",
		"application/x-bsh",
		"application/x-shar",
		"text/html",
		"text/x-server-parsed-html",
		"audio/x-psid",
		"application/x-sit",
		"application/x-stuffit",
		"application/x-koan",
		"application/x-koan",
		"application/x-koan",
		"application/x-koan",
		"application/x-seelogo",
		"application/smil",
		"application/smil",
		"audio/basic",
		"audio/x-adpcm",
		"application/solids",
		"application/x-pkcs7-certificates",
		"text/x-speech",
		"application/futuresplash",
		"application/x-sprite",
		"application/x-sprite",
		"application/x-wais-source",
		"text/x-server-parsed-html",
		"application/streamingmedia",
		"application/vnd.ms-pki.certstore",
		"application/step",
		"application/sla",
		"application/vnd.ms-pki.stl",
		"application/x-navistyle",
		"application/step",
		"application/x-sv4cpio",
		"application/x-sv4crc",
		"image/vnd.dwg",
		"image/x-dwg",
		"application/x-world",
		"x-world/x-svr",
		"application/x-shockwave-flash",
		"application/x-troff",
		"text/x-speech",
		"application/x-tar",
		"application/toolbook",
		"application/x-tbook",
		"application/x-tcl",
		"text/x-script.tcl",
		"text/x-script.tcsh",
		"application/x-tex",
		"application/x-texinfo",
		"application/x-texinfo",
		"application/plain",
		"text/plain",
		"application/gnutar",
		"application/x-compressed",
		"image/tiff",
		"image/x-tiff",
		"image/tiff",
		"image/x-tiff",
		"application/x-troff",
		"audio/tsp-audio",
		"application/dsptype",
		"audio/tsplayer",
		"text/tab-separated-values",
		"image/florian",
		"text/plain",
		"text/x-uil",
		"text/uri-list",
		"text/uri-list",
		"application/i-deas",
		"text/uri-list",
		"text/uri-list",
		"application/x-ustar",
		"multipart/x-ustar",
		"application/octet-stream",
		"text/x-uuencode",
		"text/x-uuencode",
		"application/x-cdlink",
		"text/x-vcalendar",
		"application/vda",
		"video/vdo",
		"application/groupwise",
		"video/vivo",
		"video/vnd.vivo",
		"video/vivo",
		"video/vnd.vivo",
		"application/vocaltec-media-desc",
		"application/vocaltec-media-file",
		"audio/voc",
		"audio/x-voc",
		"video/vosaic",
		"audio/voxware",
		"audio/x-twinvq-plugin",
		"audio/x-twinvq",
		"audio/x-twinvq-plugin",
		"application/x-vrml",
		"model/vrml",
		"x-world/x-vrml",
		"x-world/x-vrt",
		"application/x-visio",
		"application/x-visio",
		"application/x-visio",
		"application/wordperfect6.0",
		"application/wordperfect6.1",
		"application/msword",
		"audio/wav",
		"audio/x-wav",
		"application/x-qpro",
		"image/vnd.wap.wbmp",
		"application/vnd.xara",
		"application/msword",
		"application/x-123",
		"windows/metafile",
		"text/vnd.wap.wml",
		"application/vnd.wap.wmlc",
		"text/vnd.wap.wmlscript",
		"application/vnd.wap.wmlscriptc",
		"application/msword",
		"application/wordperfect",
		"application/wordperfect",
		"application/wordperfect6.0",
		"application/wordperfect",
		"application/wordperfect",
		"application/x-wpwin",
		"application/x-lotus",
		"application/mswrite",
		"application/x-wri",
		"application/x-world",
		"model/vrml",
		"x-world/x-vrml",
		"model/vrml",
		"x-world/x-vrml",
		"text/scriplet",
		"application/x-wais-source",
		"application/x-wintalk",
		"image/x-xbitmap",
		"image/x-xbm",
		"image/xbm",
		"video/x-amt-demorun",
		"xgl/drawing",
		"image/vnd.xiff",
		"application/excel",
		"application/excel",
		"application/x-excel",
		"application/x-msexcel",
		"application/excel",
		"application/vnd.ms-excel",
		"application/x-excel",
		"application/excel",
		"application/vnd.ms-excel",
		"application/x-excel",
		"application/excel",
		"application/x-excel",
		"application/excel",
		"application/x-excel",
		"application/excel",
		"application/vnd.ms-excel",
		"application/x-excel",
		"application/excel",
		"application/vnd.ms-excel",
		"application/x-excel",
		"application/excel",
		"application/vnd.ms-excel",
		"application/x-excel",
		"application/x-msexcel",
		"application/excel",
		"application/x-excel",
		"application/excel",
		"application/x-excel",
		"application/excel",
		"application/vnd.ms-excel",
		"application/x-excel",
		"application/x-msexcel",
		"audio/xm",
		"application/xml",
		"text/xml",
		"xgl/movie",
		"application/x-vnd.ls-xpix",
		"image/x-xpixmap",
		"image/xpm",
		"image/png",
		"video/x-amt-showrun",
		"image/x-xwd",
		"image/x-xwindowdump",
		"chemical/x-pdb",
		"application/x-compress",
		"application/x-compressed",
		"application/x-compressed",
		"application/x-zip-compressed",
		"application/zip",
		"multipart/x-zip",
		"application/octet-stream",
		"text/x-script.zsh",
		"video/mp4",
		"audio/m4a" };

}
