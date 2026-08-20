#pragma once
#ifndef KIR_EXCLUDE_STR
#include "kirkode_types.h"

#include <vector>
#include <string>
#include <type_traits> // std::is_integral, std::is_signed
#include <limits> // std::numeric_limits

namespace kir {
	/**
	 * \brief String manipulation and encoding utilities.
	 *
	 * Provides static functions for string filtering, sanitization, validation,
	 * and Base64/Base64URL encoding and decoding.
	 *
	 * Supports reusable whitelist and blacklist definitions that can be
	 * registered with a user-defined ID and applied to strings.
	 *
	 * All functions in this namespace are thread-safe and do not require instantiation.
	 */
	namespace str {
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
		 * \brief Adds a whitelist to the string cleaning logic with a given ID.
		 *
		 * \param list_id: The ID for the added whitelist.
		 * \param whitelist: The list of chars you want to be whitelisted.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool add_whitelist(std::string&& whitelist, const uint8_t list_id) noexcept;

		/**
		 * \brief Adds a blacklist to the string cleaning logic with a given ID.
		 *
		 * \param list_id: The ID for the added blacklist.
		 * \param blacklist: The list of chars you want to be blacklisted.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool add_blacklist(std::string&& blacklist, const uint8_t list_id) noexcept;

		/**
		 * \brief Cleans a string by removing every char that doesn't exists in a whitelist.
		 *
		 * \param string: The string to clean.
		 * \param list_id: The ID of the whitelist to clean the string with.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool clean_with_whitelist(std::string& string, const uint8_t list_id) noexcept;

		/**
		 * \brief Cleans a string by removing every char which exists in a blacklist.
		 *
		 * \param string: The string to clean.
		 * \param list_id: The ID of the blacklist to clean the string with.
		 * \return true if successful, false if otherwise.
		 */
		bool clean_with_blacklist(std::string& string, const uint8_t list_id) noexcept;

		/**
		 * \brief Cleans a string using a predefined cleaning preset.
		 *
		 * \param string: The string to clean.
		 * \param preset: The preset to use when cleaning the string.
		 * \param out_trimmed: Optional pointer to store the number of trimmed characters.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool clean_with_preset(std::string& string, const str_preset preset, size_t* out_trimmed = nullptr) noexcept;

		/**
		 * \brief Checks if a string is a valid Base64 encoded string.
		 *
		 * \param input: The string to validate.
		 *
		 * \return true if valid, false if otherwise.
		 */
		[[nodiscard("kir::str::is_valid_base64() is pointless without use of its return value.")]]
		bool is_valid_base64(const std::string& input) noexcept;

		/**
		 * \brief Checks if a string is a valid Base64URL encoded string.
		 *
		 * \param input: The string to validate.
		 *
		 * \return true if valid, false if otherwise.
		 */
		[[nodiscard("kir::str::is_valid_base64url() is pointless without use of its return value.")]]
		bool is_valid_base64url(const std::string& input) noexcept;

		/**
		 * \brief Encodes a string using the Base64 encoding scheme.
		 *
		 * \param string: The string to encode.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool base64_encode(std::string& string) noexcept;

		/**
		 * \brief Encodes a string using the Base64URL encoding scheme.
		 *
		 * \param string: The string to encode.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool base64url_encode(std::string& string) noexcept;

		/**
		 * \brief Decodes a Base64 encoded string.
		 *
		 * \param string: The string to decode.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool base64_decode(std::string& string) noexcept;

		/**
		 * \brief Decodes a Base64URL encoded string.
		 *
		 * \param string: The string to decode.
		 *
		 * \return true if successful, false if otherwise.
		 */
		bool base64url_decode(std::string& string) noexcept;

		/**
		 * \brief Checks to see if a string contains only digits.
		 *
		 * \param string: The string to check.
		 * \param allow_leading_sign: Optional parameter that tells if a leading '-' should be allowed in the string.
		 *
		 * \return true if all chars are digits, false if otherwise or input is empty.
		 */
		[[nodiscard("kir::str::is_digits_only() is pointless without use of its return value.")]]
		bool is_digits_only(const std::string& string, bool allow_leading_sign = false) noexcept;

		/**
		 * \brief Checks to see if a string contains only digits.
		 *
		 * \param string: The string to check.
		 *
		 * \return true if all chars are letters, false if otherwise or input is empty.
		 */
		[[nodiscard("kir::str::is_letters_only() is pointless without use of its return value.")]]
		bool is_letters_only(const std::string& string) noexcept;

		/**
		 * \brief Checks whether a character is a decimal digit ('0'–'9').
		 *
		 * \param c: The character to test.
		 *
		 * \return true if the character is a digit, false otherwise.
		 */
		[[nodiscard("kir::str::is_digit() is pointless without use of its return value.")]]
		bool is_digit(const char c) noexcept;

		/**
		 * \brief Checks whether a character is an uppercase ASCII letter ('A'–'Z').
		 *
		 * \param c: The character to test.
		 *
		 * \return true if the character is an uppercase letter, false otherwise.
		 */
		[[nodiscard("kir::str::is_uppercase_letter() is pointless without use of its return value.")]]
		bool is_uppercase_letter(const char c) noexcept;

		/**
		 * \brief Checks whether a character is a lowercase ASCII letter ('a'–'z').
		 *
		 * \param c: The character to test.
		 *
		 * \return true if the character is a lowercase letter, false otherwise.
		 */
		[[nodiscard("kir::str::is_lowercase_letter() is pointless without use of its return value.")]]
		bool is_lowercase_letter(const char c) noexcept;

		/**
		 * \brief Checks whether a character is an ASCII letter (uppercase or lowercase).
		 *
		 * \param c: The character to test.
		 *
		 * \return true if the character is a letter, false otherwise.
		 */
		[[nodiscard("kir::str::is_letter() is pointless without use of its return value.")]]
		bool is_letter(const char c) noexcept;

		/**
		 * \brief Converts a character to its uppercase equivalent if it is a lowercase letter.
		 *
		 * Non-letter characters are returned unchanged.
		 *
		 * \param c: The character to convert.
		 *
		 * \return The uppercase version of the character, or the original character if it is not a lowercase letter.
		 */
		[[nodiscard("kir::str::to_uppercase() is pointless without use of its return value.")]]
		char to_uppercase(const char c) noexcept;

		/**
		 * \brief Converts a character to its lowercase equivalent if it is an uppercase letter.
		 *
		 * Non-letter characters are returned unchanged.
		 *
		 * \param c: The character to convert.
		 *
		 * \return The lowercase version of the character, or the original character if it is not an uppercase letter.
		 */
		[[nodiscard("kir::str::to_lowercase() is pointless without use of its return value.")]]
		char to_lowercase(const char c) noexcept;

		/**
		 * \brief Converts a string to an integral value.
		 *
		 * \tparam int_type: Integral type to convert to.
		 *
		 * \param string: The string to convert.
		 * \param out: Output integral variable for converted value.
		 *
		 * \return true if successfully converted string to integral value, false if otherwise.
		 */
		template <typename int_type>
		static bool to_int(const std::string& string, int_type& out) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::str::to_int() only supports integral types!");
			out = int_type{};
			constexpr bool is_signed = std::is_signed<int_type>::value;
			if (!is_digits_only(string, is_signed)) return false;
#if KIR_CPP_STD < 201703L
			if (is_signed) {
#else
			if constexpr (is_signed) {
#endif
				int64_t i = 0;
				try { i = std::stoll(string); }
				catch (...) { return false; }
				if (i > (std::numeric_limits<int_type>::max)()) return false;
				if (i < (std::numeric_limits<int_type>::min)()) return false;
				out = static_cast<int_type>(i);
			}
			else {
				uint64_t i = 0;
				try { i = std::stoull(string); }
				catch (...) { return false; }
				if (i > (std::numeric_limits<int_type>::max)()) return false;
				out = static_cast<int_type>(i);
			}
			return true;
		}

		/**
		 * \brief Converts an integral value to a string.
		 *
		 * \tparam int_type: Integral type to convert from.
		 *
		 * \param in: The integral value to convert from.
		 * \param out: Output string for converted value.
		 *
		 * \return true if successfully converted integral value to string, false if otherwise.
		 */
		template <typename int_type>
		static bool convert_from_int(const int_type in, std::string& out) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::str::convert_from_int() only supports integral types!");
			const bool is_negative = in < int_type{};
			uint8_t digit_count = 0; {
				using uint_type = typename std::make_unsigned<int_type>::type;
				uint_type abs_value = is_negative
					? static_cast<uint_type>(0) - static_cast<uint_type>(in)
					: static_cast<uint_type>(in);
				do {
					++digit_count;
					abs_value /= 10;
				} while (abs_value != 0);
			}
			const size_t outSize = static_cast<size_t>(digit_count) + (is_negative ? 1u : 0u);
			try { out.resize(outSize); }
			catch (...) { return false; }
			using uint_type = typename std::make_unsigned<int_type>::type;
			uint_type abs_value = is_negative
				? static_cast<uint_type>(0) - static_cast<uint_type>(in)
				: static_cast<uint_type>(in);
			size_t pos = outSize;
			for (uint8_t i = 0; i < digit_count; ++i) {
				--pos;
				out[pos] = static_cast<char>((abs_value % 10) + '0');
				abs_value /= 10;
			}
			if (is_negative) out[0] = '-';
			return true;
		}

		/**
		 * \brief Converts an enum value to a string.
		 *
		 * \tparam enum_type: Enum type to convert from.
		 *
		 * \param in: The enum value to convert from.
		 * \param out: Output string for converted value.
		 *
		 * \return true if successfully converted enum value to string, false if otherwise.
		 */
		template <typename enum_type>
		static bool convert_from_enum(const enum_type in, std::string & out) noexcept {
			static_assert(!std::is_integral<enum_type>::value, "kir::str::convert_from_enum() only supports enum types! Use kir::str::convert_from_int().");
			static_assert(std::is_enum<enum_type>::value, "kir::str::convert_from_enum() only supports enum types!");
			using underlying_type = typename std::underlying_type<enum_type>::type;
			return convert_from_int<underlying_type>(static_cast<underlying_type>(in), out);
		}
	}
}
#endif // KIR_EXCLUDE_STR