#include "pch.h"
#include "kirklib.h"
#include <Windows.h>
#include <ShlObj.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <bcrypt.h>
#include <ntstatus.h>

/// #################################################################
/// This is a library created for Kirkode by Nathan Kirby
/// Feel free to use it anywhere
/// v1.04
/// #################################################################

// Strings
std::string kirklib::get_appdata(bool include_roaming) {
	try {
		wchar_t appDataPath[MAX_PATH];
		HRESULT result = SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
		std::string appdata_path;
		if (result != S_OK) {
			return "";
		}
		else {
			char AppDataFolder[MAX_PATH];
			int size_needed = WideCharToMultiByte(CP_UTF8, 0, appDataPath, -1, NULL, 0, NULL, NULL);
			WideCharToMultiByte(CP_UTF8, 0, appDataPath, -1, AppDataFolder, size_needed, NULL, NULL);
			appdata_path = std::string(AppDataFolder);
		}

		if (include_roaming) {
			return appdata_path;
		}
		else {
			return appdata_path.substr(0, appdata_path.size() - 8);
		}
	}
	catch (...) {
		return "";
	}
}

// Vector
std::vector<std::string> kirklib::string_to_vector(char delimiter, std::string input) {
	std::vector<std::string> parts;
	std::stringstream ss(input);
	std::string part;
	while (std::getline(ss, part, delimiter)) {
		parts.push_back(part);
	}
	return parts;
}

// File
std::string kirklib::get_environment_path() {
	try {
		std::vector<wchar_t> buffer(MAX_PATH);
		DWORD result = GetModuleFileName(NULL, buffer.data(), buffer.size());
		if (result == 0 || result >= buffer.size()) {
			return "";
		}

		return wstring_to_string(std::wstring(buffer.data()));
	}
	catch (...) {
		return "";
	}
}

std::string kirklib::wstring_to_string(std::wstring input) {
	try {
		int size = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), (int)input.size(), NULL, 0, NULL, NULL);
		if (size == 0) {
			return "";
		}

		std::vector<char> buffer(size);
		WideCharToMultiByte(CP_UTF8, 0, input.c_str(), (int)input.size(), buffer.data(), size, NULL, NULL);

		return std::string(buffer.data(), buffer.size());
	}
	catch (...) {
		return "";
	}
}

void kirklib::string_to_file(std::string path, std::string content) {
	try {
		std::ofstream file_stream;
		file_stream.open(path);
		if (!file_stream || !file_stream.is_open()) {
			return;
		}

		file_stream << content << std::endl;
		file_stream.close();
	}
	catch (...) {
		return;
	}
}

std::string kirklib::read_all_text(std::string path) {
	try {
		if (!file_exists(path)) {
			return "";
		}

		std::ifstream file_stream(path);
		if (!file_stream) {
			return "";
		}

		std::stringstream buffer;
		buffer << file_stream.rdbuf();
		std::string file_content = buffer.str();
		file_stream.close();

		return file_content;
	}
	catch (...) {
		return "";
	}
}

void kirklib::delete_file(std::string path) {
	try {
		if (file_exists(path)) {
			remove(path.c_str());
		}
	}
	catch (...) {
		return;
	}
}

bool kirklib::file_exists(std::string path) {
	try {
		std::ifstream file_stream(path);
		if (file_stream.good()) {
			return true;
		}
		return false;
	}
	catch (...) {
		return false;
	}
}

std::string kirklib::get_file_checksum(std::string path) {
	try {
		BCRYPT_ALG_HANDLE hAlgo = nullptr;
		BCRYPT_HASH_HANDLE hHash = nullptr;
		NTSTATUS status = 0;
		DWORD cbData = 0, cbHashObject = 0, cbHash = 0;
		std::vector<BYTE> pbHashObject;
		std::vector<BYTE> pbHash;

		// Open an algorithm handle and get it's status 
		status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_SHA256_ALGORITHM, NULL, 0);
		if (!BCRYPT_SUCCESS(status)) {
			return "";
		}

		// Calculate the size of the buffer to hold the hash object and get it's status
		status = BCryptGetProperty(hAlgo, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
		if (!BCRYPT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hAlgo, 0);
			return "";
		}

		pbHashObject.resize(cbHashObject);

		// Calculate the length of the hash
		status = BCryptGetProperty(hAlgo, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
		if (!BCRYPT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hAlgo, 0);
			return "";
		}

		pbHash.resize(cbHash);

		// Create a hash
		status = BCryptCreateHash(hAlgo, &hHash, pbHashObject.data(), cbHashObject, NULL, 0, 0);
		if (!BCRYPT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hAlgo, 0);
			return "";
		}

		// Open the file
		std::ifstream file(path, std::ios::binary);
		if (!file.is_open()) {
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hAlgo, 0);
			return "";
		}

		// Read file and hash data
		std::vector<char> buffer(8192);
		while (file.good()) {
			file.read(buffer.data(), buffer.size());
			status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buffer.data()), file.gcount(), 0);
			if (!BCRYPT_SUCCESS(status)) {
				BCryptDestroyHash(hHash);
				BCryptCloseAlgorithmProvider(hAlgo, 0);
				return "";
			}
		}

		// Finalize the hash
		status = BCryptFinishHash(hHash, pbHash.data(), cbHash, 0);
		if (!BCRYPT_SUCCESS(status)) {
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hAlgo, 0);
			return "";
		}

		// Cleanup
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlgo, 0);

		// Convert hash to hex string
		std::stringstream ss;
		for (BYTE b : pbHash) {
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
		}

		return ss.str();
	}
	catch (...) {
		return "";
	}
}