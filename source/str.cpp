#include "impl/kirkode_str.h"

#include <cctype> // std::isalpha, std::isdigit

namespace kir {
	bool str::add_whitelist(std::string&& whitelist, const uint8_t listId) noexcept {
		listMutex.lock();
		try {
			if (whitelistMap.find(listId) != whitelistMap.end()) {
				listMutex.unlock();
				return false;
			}
			whitelistMap.emplace(listId, std::move(whitelist));
		}
		catch (...) {
			listMutex.unlock();
			return false;
		}
		listMutex.unlock();
		return true;
	}
	bool str::add_blacklist(std::string&& blacklist, const uint8_t listId) noexcept {
		listMutex.lock();
		try {
			if (blacklistMap.find(listId) != blacklistMap.end()) {
				listMutex.unlock();
				return false;
			}
			blacklistMap.emplace(listId, std::move(blacklist));
		}
		catch (...) {
			listMutex.unlock();
			return false;
		}
		listMutex.unlock();
		return true;
	}
	bool str::clean_with_whitelist(std::string& string, const uint8_t listId) noexcept {
		if (string.empty()) return false;
		listMutex.lock();
		std::string cleaned;
		try {
			const auto it = whitelistMap.find(listId);
			if (it == whitelistMap.end()) {
				listMutex.unlock();
				return false;
			}
			cleaned.reserve(string.size());
			for (char c : string) {
				if (std::find(it->second.begin(), it->second.end(), c) != it->second.end()) {
					cleaned.push_back(c);
				}
			}
			cleaned.shrink_to_fit();
		}
		catch (...) {
			listMutex.unlock();
			return false;
		}
		listMutex.unlock();
		string.swap(cleaned);
		return true;
	}
	bool str::clean_with_blacklist(std::string& string, const uint8_t listId) noexcept {
		if (string.empty()) return false;
		listMutex.lock();
		std::string cleaned;
		try {
			const auto it = blacklistMap.find(listId);
			if (it == blacklistMap.end()) {
				listMutex.unlock();
				return false;
			}
			cleaned.reserve(string.size());
			for (char c : string) {
				if (std::find(it->second.begin(), it->second.end(), c) == it->second.end()) {
					cleaned.push_back(c);
				}
			}
			cleaned.shrink_to_fit();
		}
		catch (...) {
			listMutex.unlock();
			return false;
		}
		listMutex.unlock();
		string.swap(cleaned);
		return true;
	}
	bool str::clean_with_preset(std::string& string, const str_preset preset, size_t* outTrimmed) noexcept {
		static const std::string file_preset = " -_.()[]{}`'~";
		if (outTrimmed) *outTrimmed = 0;
		if (string.empty()) return false;
		if (preset == str_preset::NONE) return false;
		std::string cleaned;
		try {
			cleaned.reserve(string.size());
			if (preset == str_preset::NUMERIC) {
				for (char c : string) {
					if (std::isdigit(c)) {
						cleaned.push_back(c);
					}
				}
			}
			else if (preset == str_preset::ALPHA) {
				for (char c : string) {
					if (std::isalpha(c)) {
						cleaned.push_back(c);
					}
				}
			}
			else if (preset == str_preset::ALPHANUMERIC) {
				for (char c : string) {
					if (std::isalpha(c) || std::isdigit(c)) {
						cleaned.push_back(c);
					}
				}
			}
			else if (preset == str_preset::PRINTABLE) {
				for (char c : string) {
					if (c >= 32 && c <= 126) {
						cleaned.push_back(c);
					}
				}
			}
			else if (preset == str_preset::ONE_LINE) {
				for (char c : string) {
					if (c >= 32) {
						cleaned.push_back(c);
					}
				}
			}
			else if (preset == str_preset::FILE) {
				for (char c : string) {
					if (std::isalpha(c) ||
						std::isdigit(c) ||
						std::find(file_preset.begin(), file_preset.end(), c) != file_preset.end()
						) {
						cleaned.push_back(c);
					}
				}
			}
			cleaned.shrink_to_fit();
		}
		catch (...) {
			return false;
		}
		if (outTrimmed) *outTrimmed = string.size() - cleaned.size();
		string.swap(cleaned);
		return true;
	}
	 bool str::is_digits_only(const std::string& string, bool allowLeadingSign) noexcept {
		if (string.empty()) return false;
		if (!allowLeadingSign) {
			for (const char c : string) {
				if (!std::isdigit(c)) return false;
			}
		}
		else {
			const size_t len = string.size();
			const bool isSigned = string[0] == '-';
			if (isSigned && len <= 1) return false;
			size_t i = isSigned ? 1 : 0;
			for (; i < len; ++i) {
				if (!std::isdigit(string[i])) return false;
			}
		}
		return true;
	 }
}

namespace kir {
	static constexpr char base64_table[65] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
	static constexpr char base64url_table[65] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789-_";
	static constexpr int8_t base64_decode_table[256] = {
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
		52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
		-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	};
	static constexpr int8_t base64url_decode_table[256] = {
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
		52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
		-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	};
	static bool internal_valid_base64(const std::string& input, const size_t inputSize, const int8_t(&decodeTable)[256]) noexcept {
		if (inputSize == 0) return false;
		uint8_t pad = 0;
		for (size_t i = 0; i < inputSize; ++i) {
			const uint8_t c = static_cast<uint8_t>(input[i]);
			if (c != static_cast<uint8_t>('=')) {
				if (pad > 0) return false;
				if (decodeTable[c] < 0) return false;
			}
			else {
				if (pad >= 2) return false;
				++pad;
			}
		}
		const size_t dataLen = inputSize - pad;
		if (dataLen % 4 == 1) return false;
		if (pad > 0 && inputSize % 4 != 0) return false;
		if (pad == 1 && dataLen % 4 != 3) return false;
		if (pad == 2 && dataLen % 4 != 2) return false;
		return true;
	}
	static bool internal_base64_encode(std::string& string, const char(&table)[65], const bool usePadding) noexcept {
		std::string output;
		const size_t inputSize = string.size();
		if (inputSize == 0) return false;
		if (inputSize > ((output.max_size() - 2) / 4) * 3) return false;
		try {
			output.reserve(((inputSize + 2) / 3) * 4);
			uint32_t val = 0;
			int32_t bits = -6;
			for (unsigned char c : string) {
				val = (val << 8) + c;
				bits += 8;
				while (bits >= 0) {
					output.push_back(table[(val >> bits) & 0x3F]);
					bits -= 6;
				}
			}
			if (bits > -6) {
				output.push_back(table[((val << 8) >> (bits + 8)) & 0x3F]);
			}
			if (usePadding) {
				while (output.size() % 4) output.push_back('=');
			}
		}
		catch (...) {
			return false;
		}
		string.swap(output);
		return true;
	}
	static bool internal_base64_decode(std::string& string, const char(&encodeTable)[65], const int8_t(&decodeTable)[256]) noexcept {
		const size_t inputSize = string.size();
		if (!internal_valid_base64(string, inputSize, decodeTable)) return false;
		std::string output;
		try {
			output.reserve((inputSize / 4) * 3);
			uint32_t val = 0;
			int32_t bits = -8;
			for (size_t i = 0; i < inputSize; ++i) {
				unsigned char c = string[i];
				if (c == '=') break;
				int8_t decoded = decodeTable[c];
				if (decoded < 0) return false;
				val = (val << 6) | decoded;
				bits += 6;
				if (bits >= 0) {
					output.push_back(static_cast<char>((val >> bits) & 0xFF));
					bits -= 8;
				}
			}
		}
		catch (...) {
			return false;
		}
		string.swap(output);
		return true;
	}
}

namespace kir {
	bool str::is_valid_base64(const std::string& input, const size_t inputSize) noexcept {
		return internal_valid_base64(input, inputSize, base64_decode_table);
	}
	bool str::is_valid_base64url(const std::string& input, const size_t inputSize) noexcept {
		return internal_valid_base64(input, inputSize, base64url_decode_table);
	}
	bool str::base64_encode(std::string& string) noexcept {
		return internal_base64_encode(string, base64_table, true);
	}
	bool str::base64url_encode(std::string& string) noexcept {
		return internal_base64_encode(string, base64url_table, false);
	}
	bool str::base64_decode(std::string& string) noexcept {
		return internal_base64_decode(string, base64_table, base64_decode_table);
	}
	bool str::base64url_decode(std::string& string) noexcept {
		return internal_base64_decode(string, base64url_table, base64url_decode_table);
	}
}