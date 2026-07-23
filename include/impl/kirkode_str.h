#pragma once

#include "kirkode_types.h"

#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>

namespace kir {
	/**
	* \brief Defines predefined string cleaning presets.
	* 
	* Use with kir::str::clean_with_preset().
	*/
	enum class str_preset : uint8_t {
		NONE,
		NUMERIC, // Keep only numbers.
		ALPHA, // Keep only letters.
		ALPHANUMERIC, // Keep only letters and numbers.
		PRINTABLE, // Keep only printable ASCII chars.
		ONE_LINE, // Removes all new lines or blank spaces.
		FILE // Removes all chars not safe for file paths.
	};

	/**
	 * \brief String manipulation and encoding utilities.
	 *
	 * Provides static functions for string filtering, sanitization, validation,
	 * and Base64/Base64URL encoding and decoding.
	 *
	 * Supports reusable whitelist and blacklist definitions that can be
	 * registered with a user-defined ID and applied to strings.
	 *
	 * This class is thread-safe and does not require instantiation.
	 */
	class str {
	private:
		inline static std::mutex listMutex;
		inline static std::unordered_map<uint8_t, std::string> whitelistMap;
		inline static std::unordered_map<uint8_t, std::string> blacklistMap;
	public:
		/**
		* \brief Adds a whitelist to the string cleaning logic with a given ID.
		*
		* \param listId: The ID for the added whitelist.
		* \param whitelist: The list of chars you want to be whitelisted.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool add_whitelist(std::string&& whitelist, const uint8_t listId) noexcept;

		/**
		* \brief Adds a blacklist to the string cleaning logic with a given ID.
		*
		* \param listId: The ID for the added blacklist.
		* \param blacklist: The list of chars you want to be blacklisted.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool add_blacklist(std::string&& blacklist, const uint8_t listId) noexcept;
	public:
		/**
		* \brief Cleans a string by removing every char that doesn't exists in a whitelist.
		*
		* \param string: The string to clean.
		* \param listId: The ID of the whitelist to clean the string with.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool clean_with_whitelist(std::string& string, const uint8_t listId) noexcept;

		/**
		* \brief Cleans a string by removing every char which exists in a blacklist.
		* 
		* \param string: The string to clean.
		* \param listId: The ID of the blacklist to clean the string with.
		* 
		* \return true if successful, false if otherwise.
		*/
		static bool clean_with_blacklist(std::string& string, const uint8_t listId) noexcept;
	public:
		/**
		* \brief Cleans a string using a predefined cleaning preset.
		*
		* \param string: The string to clean.
		* \param preset: The preset to use when cleaning the string.
		* \param outTrimmed: Optional pointer to store the number of trimmed characters.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool clean_with_preset(std::string& string, const str_preset preset, size_t* outTrimmed = nullptr) noexcept;
	public:
		/**
		* \brief Checks if a string is a valid Base64 encoded string.
		*
		* \param input: The string to validate.
		* \param inputSize: The size of the string to validate.
		*
		* \return true if valid, false if otherwise.
		*/
		[[nodiscard("kir::str::is_valid_base64() is pointless without use of its return value.")]]
		static bool is_valid_base64(const std::string& input, const size_t inputSize) noexcept;

		/**
		* \brief Checks if a string is a valid Base64URL encoded string.
		*
		* \param input: The string to validate.
		* \param inputSize: The size of the string to validate.
		*
		* \return true if valid, false if otherwise.
		*/
		[[nodiscard("kir::str::is_valid_base64url() is pointless without use of its return value.")]]
		static bool is_valid_base64url(const std::string& input, const size_t inputSize) noexcept;

		/**
		* \brief Encodes a string using the Base64 encoding scheme.
		*
		* \param string: The string to encode.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool base64_encode(std::string& string) noexcept;

		/**
		* \brief Encodes a string using the Base64URL encoding scheme.
		*
		* \param string: The string to encode.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool base64url_encode(std::string& string) noexcept;

		/**
		* \brief Decodes a Base64 encoded string.
		*
		* \param string: The string to decode.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool base64_decode(std::string& string) noexcept;

		/**
		* \brief Decodes a Base64URL encoded string.
		*
		* \param string: The string to decode.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool base64url_decode(std::string& string) noexcept;
	};
}