#pragma once
#ifndef KIR_EXCLUDE_BIN
#include "kirkode_types.h"

#include <string>
#include <cstring> // std::memcpy
#include <type_traits> // std::is_integral
#include <limits> // std::numeric_limits
#include <stdexcept> // std::invalid_argument

namespace kir {
	/**
	 * \brief Binary serialization and deserialization utilities.
	 *
	 * Provides static functions for packing and unpacking primitive values
	 * into and from raw byte buffers.
	 *
	 * Supported data types include:
	 * 1: Integral values.
	 * 2: Floating-point values.
	 * 3: Strings.
	 *
	 * Functions support multiple usage styles:
	 * 1: Reading/writing at a fixed offset.
	 * 2: Streaming-style operations with automatic offset advancement.
	 * 3: Return-value convenience wrappers.
	 * 4: Exception-based variants.
	 *
	 * Integer values are encoded using little-endian byte order.
	 * Floating-point values use their native binary representation.
	 * Strings are stored as a length value followed by raw character data.
	 *
	 * This class is entirely static and does not require instantiation.
	 */
	namespace bin {
		/**
		 * \brief Writes an integer into a buffer at a specific offset.
		 * The value is encoded in little-endian format.
		 * No resizing is performed; the buffer must already be large enough.
		 *
		 * \tparam int_type: Integral type to write.
		 *
		 * \param buffer: Destination byte buffer.
		 * \param offset: Position in buffer to write at.
		 * \param value: Integer value to encode.
		 *
		 * \return true if the value was written successfully, false if the buffer is too small.
		 */
		template <typename int_type>
		static bool pack_int_at(kir::bytes& buffer, const size_t offset, const int_type value) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::bin::pack_int_at() only supports integral types!");
			static_assert(sizeof(int_type) < 0xFF, "kir::bin::pack_int_at() only supports types smaller than 0xFF!");
			if (offset + sizeof(int_type) > buffer.size()) return false;
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				using uint_type = typename std::make_unsigned<int_type>::type;
				const uint_type unsignedValue = static_cast<uint_type>(value);
				for (uint8_t i = 0; i < sizeof(int_type); ++i) {
					buffer[offset + i] = static_cast<kir::byte>((unsignedValue >> (i * 8)) & 0xFF);
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(int_type); ++i) {
					buffer[offset + i] = static_cast<kir::byte>((value >> (i * 8)) & 0xFF);
				}
			}
			return true;
		}

		/**
		 * \brief Writes an integer into a buffer and advances the offset.
		 * Acts like a streaming writer: after writing, the offset is incremented
		 * by sizeof(int_type).
		 *
		 * \tparam int_type Integral type to write.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param value: Integer value to encode.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename int_type>
		static bool pack_int_at(size_t& offset, kir::bytes& buffer, const int_type value) noexcept {
			if (!pack_int_at<int_type>(buffer, offset, value)) {
				return false;
			}
			offset += sizeof(int_type);
			return true;
		}

		/**
		 * \brief Appends an integer to the end of a byte buffer.
		 * The buffer is resized automatically if needed.
		 * The value is encoded in little-endian format.
		 *
		 * \tparam int_type: Integral type to write.
		 *
		 * \param buffer: Destination byte buffer (will grow).
		 * \param value: Integer value to encode.
		 *
		 * \return true if the value was successfully appended, false on allocation failure.
		 */
		template <typename int_type>
		static bool pack_int(kir::bytes& buffer, const int_type value) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::bin::pack_int() only supports integral types!");
			static_assert(sizeof(int_type) < 0xFF, "kir::bin::pack_int() only supports types smaller than 0xFF!");
			try {
				buffer.reserve(buffer.size() + sizeof(int_type));
			}
			catch (...) { return false; }
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				using uint_type = typename std::make_unsigned<int_type>::type;
				const uint_type usigned_value = static_cast<uint_type>(value);
				for (uint8_t i = 0; i < sizeof(uint_type); ++i) {
					buffer.push_back(static_cast<kir::byte>((usigned_value >> (i * 8)) & 0xFF));
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(int_type); ++i) {
					buffer.push_back(static_cast<kir::byte>((value >> (i * 8)) & 0xFF));
				}
			}
			return true;
			}

		/**
		 * \brief Reads an integer from a buffer at a specific offset.
		 * The value is decoded using little-endian format.
		 *
		 * \tparam int_type Integral type to read.
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer to read from.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename int_type>
		static bool unpack_int_at(const kir::bytes& buffer, const size_t offset, int_type& out) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::bin::unpack_int_at() only supports integral types!");
			static_assert(sizeof(int_type) < 0xFF, "kir::bin::unpack_int_at() only supports types smaller than 0xFF!");
			if (offset + sizeof(int_type) > buffer.size()) return false;
			out = int_type{};
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				using uint_type = typename std::make_unsigned<int_type>::type;
				for (uint8_t i = 0; i < sizeof(uint_type); ++i) {
					out |= static_cast<int_type>(static_cast<uint_type>(buffer[offset + i]) << (8 * i));
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(int_type); ++i) {
					out |= static_cast<int_type>(buffer[offset + i]) << (8 * i);
				}
			}
			return true;
			}

		/**
		 * \brief Reads an integer from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * \tparam int_type: Integral type to read.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename int_type>
		static bool unpack_int_at(size_t& offset, const kir::bytes& buffer, int_type& out) noexcept {
			if (!unpack_int_at<int_type>(buffer, offset, out)) {
				return false;
			}
			offset += sizeof(int_type);
			return true;
		}

		/**
		 * \brief Reads an integer from a buffer and returns it.
		 * This is a convenience wrapper that does not use an output parameter.
		 *
		 * \tparam int_type: Integral type to read.
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 * \param out_success: Optional output flag indicating success or failure.
		 *
		 * \return Decoded integer value, or 0 on failure.
		 */
		template <typename int_type>
		[[nodiscard("kir::bin::unpack_int_at_r() is pointless without use of its return value.")]]
		static int_type unpack_int_at_r(const kir::bytes& buffer, const size_t offset, bool* out_success = nullptr) noexcept {
			int_type out = int_type{};
			if (!unpack_int_at<int_type>(buffer, offset, out)) {
				if (out_success) *out_success = false;
				return int_type{};
			}
			if (out_success) *out_success = true;
			return out;
		}

		/**
		 * \brief Reads an integer from a buffer, returns it, and advances the offset.
		 * This behaves like a streaming reader with return-style output.
		 *
		 * \tparam int_type: Integral type to read.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out_success: Optional output flag indicating success or failure.
		 *
		 * \return Decoded integer value, or 0 on failure.
		 */
		template <typename int_type>
		[[nodiscard("kir::bin::unpack_int_at_r() is pointless without use of its return value.")]]
		static int_type unpack_int_at_r(size_t & offset, const kir::bytes & buffer, bool* out_success = nullptr) noexcept {
			int_type out = int_type{};
			if (!unpack_int_at<int_type>(buffer, offset, out)) {
				if (out_success) *out_success = false;
				return int_type{};
			}
			offset += sizeof(int_type);
			if (out_success) *out_success = true;
			return out;
		}

		/**
		 * \brief Reads an integer from a buffer or throws on failure.
		 * If the buffer does not contain enough data, an exception is thrown.
		 *
		 * \tparam int_type: Integral type to read.
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 *
		 * \return Decoded integer value.
		 *
		 * \throws std::invalid_argument If the buffer is too small.
		 */
		template <typename int_type>
		[[nodiscard("kir::bin::unpack_int_at_e() is pointless without use of its return value.")]]
		static int_type unpack_int_at_e(const kir::bytes& buffer, const size_t offset) {
			static_assert(std::is_integral<int_type>::value, "kir::bin::unpack_int_at_e() only supports integral types!");
			static_assert(sizeof(int_type) < 0xFF, "kir::bin::unpack_int_at_e() only supports types smaller than 0xFF!");
			if (offset + sizeof(int_type) > buffer.size()) throw std::invalid_argument("Buffer too small!");
			int_type out = int_type{};
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				using uint_type = typename std::make_unsigned<int_type>::type;
				for (uint8_t i = 0; i < sizeof(uint_type); ++i) {
					out |= static_cast<int_type>(static_cast<uint_type>(buffer[offset + i]) << (8 * i));
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(int_type); ++i) {
					out |= static_cast<int_type>(buffer[offset + i]) << (8 * i);
				}
			}
			return out;
			}

		/**
		 * \brief Reads an integer, advances offset, or throws on failure.
		 * Streaming variant of the exception-based reader.
		 *
		 * \tparam int_type: Integral type to read.
		 *
		 * \param offset: Position in buffer (will be advanced).
		 * \param buffer: Source byte buffer.
		 *
		 * \return Decoded integer value.
		 *
		 * \throws std::invalid_argument If the buffer is too small.
		 */
		template <typename int_type>
		[[nodiscard("kir::bin::unpack_int_at_e() is pointless without use of its return value.")]]
		static int_type unpack_int_at_e(size_t& offset, const kir::bytes& buffer) {
			const int_type out = unpack_int_at_e<int_type>(buffer, offset);
			offset += sizeof(int_type);
			return out;
		}

		/**
		 * \brief Writes a floating-point value into a buffer at a specific offset.
		 * The raw binary representation of the value is copied into the buffer.
		 * No resizing is performed; the buffer must already be large enough.
		 *
		 * \tparam float_type: Floating-point type to write (default: float).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param offset: Position in buffer to write at.
		 * \param value: Floating-point value to encode.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename float_type = float>
		static bool pack_float_at(kir::bytes& buffer, const size_t offset, const float_type value) noexcept {
			static_assert(std::is_floating_point<float_type>::value, "kir::bin::pack_float_at() only supports floating point types!");
			if (offset + sizeof(float_type) > buffer.size()) return false;
			std::memcpy(&buffer[offset], &value, sizeof(float_type));
			return true;
		}

		/**
		 * \brief Writes a floating-point value into a buffer and advances the offset.
		 * Acts like a streaming writer: after writing, the offset is incremented
		 * by sizeof(float_type).
		 *
		 * \tparam float_type: Floating-point type to write (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param value: Floating-point value to encode.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename float_type = float>
		static bool pack_float_at(size_t& offset, kir::bytes& buffer, const float_type value) noexcept {
			if (!pack_float_at<float_type>(buffer, offset, value)) {
				return false;
			}
			offset += sizeof(float_type);
			return true;
		}

		/**
		 * \brief Appends a floating-point value to the end of a byte buffer.
		 * The buffer is resized automatically if needed.
		 * The raw binary representation of the value is appended.
		 *
		 * \tparam float_type: Floating-point type to write (default: float).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param value: Floating-point value to encode.
		 *
		 * \return true if successful, false on allocation failure.
		 */
		template <typename float_type = float>
		static bool pack_float(kir::bytes& buffer, const float_type value) noexcept {
			static_assert(std::is_floating_point<float_type>::value, "kir::bin::pack_float() only supports floating point types!");
			const size_t old_size = buffer.size();
			try {
				buffer.resize(old_size + sizeof(float_type));
			}
			catch (...) { return false; }
			std::memcpy(&buffer[old_size], &value, sizeof(float_type));
			return true;
		}

		/**
		 * \brief Reads a floating-point value from a buffer at a specific offset.
		 * Reads the raw binary representation from the buffer into the output value.
		 *
		 * \tparam float_type: Floating-point type to read (default: float).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer to read from.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename float_type = float>
		static bool unpack_float_at(const kir::bytes& buffer, const size_t offset, float_type& out) noexcept {
			static_assert(std::is_floating_point<float_type>::value, "kir::bin::unpack_float_at() only supports floating point types!");
			if (offset + sizeof(float_type) > buffer.size()) return false;
			std::memcpy(&out, buffer.data() + offset, sizeof(float_type));
			return true;
		}

		/**
		 * \brief Reads a floating-point value from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * \tparam float_type: Floating-point type to read (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename float_type = float>
		static bool unpack_float_at(size_t& offset, const kir::bytes& buffer, float_type& out) noexcept {
			if (!unpack_float_at<float_type>(buffer, offset, out)) {
				return false;
			}
			offset += sizeof(float_type);
			return true;
		}

		/**
		 * \brief Reads a floating-point value from a buffer and returns it.
		 * This is a convenience wrapper that does not use an output parameter.
		 *
		 * \tparam float_type: Floating-point type to read (default: float).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 * \param out_success: Optional output flag indicating success or failure.
		 *
		 * \return Decoded value, or 0.0f on failure.
		 */
		template <typename float_type = float>
		[[nodiscard("kir::bin::unpack_float_at_r() is pointless without use of its return value.")]]
		static float_type unpack_float_at_r(const kir::bytes& buffer, const size_t offset, bool* out_success = nullptr) noexcept {
			float_type out = float_type{};
			if (!unpack_float_at<float_type>(buffer, offset, out)) {
				if (out_success) *out_success = false;
				return float_type{};
			}
			if (out_success) *out_success = true;
			return out;
		}

		/**
		 * \brief Reads a floating-point value, returns it, and advances the offset.
		 * This behaves like a streaming reader with return-style output.
		 *
		 * \tparam float_type: Floating-point type to read (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out_success: Optional output flag indicating success or failure.
		 *
		 * \return Decoded value, or 0.0f on failure.
		 */
		template <typename float_type = float>
		[[nodiscard("kir::bin::unpack_float_at_r() is pointless without use of its return value.")]]
		static float_type unpack_float_at_r(size_t& offset, const kir::bytes& buffer, bool* out_success = nullptr) noexcept {
			float_type out = float_type{};
			if (!unpack_float_at<float_type>(buffer, offset, out)) {
				if (out_success) *out_success = false;
				return float_type{};
			}
			offset += sizeof(float_type);
			if (out_success) *out_success = true;
			return out;
		}

		/**
		 * \brief Reads a floating-point value from a buffer or throws on failure.
		 * If the buffer does not contain enough data, an exception is thrown.
		 *
		 * \tparam float_type: Floating-point type to read (default: float).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 *
		 * \return Decoded floating-point value.
		 *
		 * \throws std::invalid_argument: Buffer does not contain enough data.
		 */
		template <typename float_type = float>
		[[nodiscard("kir::bin::unpack_float_at_e() is pointless without use of its return value.")]]
		static float_type unpack_float_at_e(const kir::bytes& buffer, const size_t offset) {
			static_assert(std::is_floating_point<float_type>::value, "kir::bin::unpack_float_at_e() only supports floating point types!");
			if (offset + sizeof(float_type) > buffer.size()) throw std::invalid_argument("Buffer too small!");
			float_type out = float_type{};
			std::memcpy(&out, buffer.data() + offset, sizeof(float_type));
			return out;
		}

		/**
		 * \brief Reads a floating-point value, advances the offset, or throws on failure.
		 * Streaming variant of the exception-based reader.
		 *
		 * \tparam float_type: Floating-point type to read (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 *
		 * \return Decoded floating-point value.
		 *
		 * \throws std::invalid_argument: Buffer does not contain enough data.
		 */
		template <typename float_type = float>
		[[nodiscard("kir::bin::unpack_float_at_e() is pointless without use of its return value.")]]
		static float_type unpack_float_at_e(size_t& offset, const kir::bytes& buffer) {
			const float_type out = unpack_float_at_e<float_type>(buffer, offset);
			offset += sizeof(float_type);
			return out;
		}

		/**
		 * \brief Writes a string into a buffer at a specific offset.
		 * The string is stored as a length value followed by the raw string data.
		 * No resizing is performed; the buffer must already be large enough.
		 *
		 * \tparam size_type: Unsigned integral type used for storing string length (default: uint16_t).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param offset: Position in buffer to write at.
		 * \param str: String to encode.
		 *
		 * \return true if successful, false if the buffer is too small
		 * or the string exceeds the maximum representable length.
		 */
		template <typename size_type = uint16_t>
		static bool pack_str_at(kir::bytes& buffer, const size_t offset, const std::string& str) noexcept {
			static_assert(std::is_integral<size_type>::value, "kir::bin::pack_str_at() only supports unsigned integral types!");
			static_assert(!std::is_signed<size_type>::value, "kir::bin::pack_str_at() only supports unsigned integral types!");
			if ((std::numeric_limits<size_type>::max)() < str.size()) return false;
			const size_type len = static_cast<size_type>(str.size());
			if (offset + sizeof(size_type) + len > buffer.size()) return false;
			std::memcpy(buffer.data() + offset, &len, sizeof(size_type));
			std::memcpy(buffer.data() + offset + sizeof(size_type), str.data(), len);
			return true;
		}

		/**
		 * \brief Writes a string into a buffer and advances the offset.
		 * Acts like a streaming writer: after writing, the offset is incremented
		 * by the size of the stored length and string data.
		 *
		 * \tparam size_type: Unsigned integral type used for storing string length (default: uint16_t).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param str: String to encode.
		 *
		 * \return true if successful, false if the buffer is too small
		 * or the string exceeds the maximum representable length.
		 */
		template <typename size_type = uint16_t>
		static bool pack_str_at(size_t& offset, kir::bytes& buffer, const std::string& str) noexcept {
			if (!pack_str_at<size_type>(buffer, offset, str)) {
				return false;
			}
			offset += sizeof(size_type) + str.size();
			return true;
		}

		/**
		 * \brief Appends a string to the end of a byte buffer.
		 * The string is stored as a length value followed by the raw string data.
		 * The buffer is resized automatically if needed.
		 *
		 * \tparam size_type: Unsigned integral type used for storing string length (default: uint16_t).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param str: String to encode.
		 *
		 * \return true if successful, false if allocation fails
		 * or the string exceeds the maximum representable length.
		 */
		template <typename size_type = uint16_t>
		static bool pack_str(kir::bytes& buffer, const std::string& str) noexcept {
			static_assert(std::is_integral<size_type>::value, "kir::bin::pack_str() only supports unsigned integral types!");
			static_assert(!std::is_signed<size_type>::value, "kir::bin::pack_str() only supports unsigned integral types!");
			if ((std::numeric_limits<size_type>::max)() < str.size()) return false;
			const size_type len = static_cast<size_type>(str.size());
			const size_t buffer_len = buffer.size();
			try { buffer.resize(buffer_len + sizeof(size_type) + len); }
			catch (...) { return false; }
			std::memcpy(buffer.data() + buffer_len, &len, sizeof(size_type));
			std::memcpy(buffer.data() + buffer_len + sizeof(size_type), str.data(), len);
			return true;
		}

		/**
		 * \brief Reads a string from a buffer at a specific offset.
		 * Expects the string to be stored as a length value followed by raw string data.
		 *
		 * \tparam size_type: Unsigned integral type used for reading string length (default: uint16_t).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer to read from.
		 * \param out: Output string for decoded data.
		 *
		 * \return true if successful, false if the buffer does not contain
		 * enough data or string allocation fails.
		 */
		template <typename size_type = uint16_t>
		static bool unpack_str_at(const kir::bytes& buffer, const size_t offset, std::string& out) noexcept {
			static_assert(std::is_integral<size_type>::value, "kir::bin::unpack_str_at() only supports integral types!");
			static_assert(!std::is_signed<size_type>::value, "kir::bin::unpack_str_at() only supports unsigned types!");
			if (offset + sizeof(size_type) > buffer.size()) return false;
			size_type len = size_type{};
			std::memcpy(&len, buffer.data() + offset, sizeof(size_type));
			if (offset + sizeof(size_type) + len > buffer.size()) return false;
			if (out.size() != len) out.resize(len);
			try { out.assign(reinterpret_cast<const char*>(buffer.data() + offset + sizeof(size_type)), len); }
			catch (...) { return false; }
			return true;
		}

		/**
		 * \brief Reads a string from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * \tparam size_type: Unsigned integral type used for reading string length (default: uint16_t).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output string for decoded data.
		 *
		 * \return true if successful, false if the buffer does not contain
		 * enough data or string allocation fails.
		 */
		template <typename size_type = uint16_t>
		static bool unpack_str_at(size_t& offset, const kir::bytes& buffer, std::string& out) noexcept {
			if (!unpack_str_at<size_type>(buffer, offset, out)) {
				return false;
			}
			offset += sizeof(size_type) + out.size();
			return true;
		}

		/**
		 * \brief Writes a trivially copyable class/struct to a buffer and advances the offset.
		 * Acts like a streaming writer.
		 *
		 * Copies the raw memory representation of the object into the destination buffer.
		 * The type must have a standard layout and be safe for binary copying.
		 *
		 * \tparam class_type: Class/struct type to write.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param value: Object to encode into the buffer.
		 *
		 * \return true if successful, false if the buffer does not contain
		 * enough space for the object.
		 */
		template <typename class_type>
		static bool pack_class_at(size_t& offset, kir::bytes& buffer, const class_type& value) noexcept {
			static_assert(std::is_class<class_type>::value, "kir::bin::pack_class_at() only accepts class or struct types!");
			static_assert(std::is_trivially_copyable<class_type>::value, "kir::bin::pack_class_at() only accepts types that are trivially copyable!");
			static_assert(std::is_standard_layout<class_type>::value, "kir::bin::pack_class_at() only accepts types with a standard layout!");
			static_assert(sizeof(class_type) > 1, "kir::bin::pack_class_at() does not accept empty classes!");
			if (offset + sizeof(class_type) > buffer.size()) return false;
			std::memcpy(buffer.data() + offset, &value, sizeof(class_type));
			offset += sizeof(class_type);
			return true;
		}

		/**
		 * \brief Reads a trivially copyable class/struct from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * Copies raw bytes from the buffer into the output object.
		 * An optional size override can be used when reading data produced by
		 * a different compiler, framework, or binary format with a different
		 * structure size due to padding or packing differences.
		 *
		 * \tparam class_type: Class/struct type to read.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output object for decoded data.
		 * \param size_override: Number of bytes to read instead of sizeof(class_type)
		 * (default: sizeof(class_type)).
		 *
		 * \return true if successful, false if the buffer does not contain
		 * enough data or the requested read size exceeds the object size.
		 */
		template <typename class_type>
		static bool unpack_class_at(size_t& offset, const kir::bytes& buffer, class_type& out, const size_t size_override = 0) noexcept {
			static_assert(std::is_class<class_type>::value, "kir::bin::unpack_class_at() only accepts class or struct types!");
			static_assert(std::is_trivially_copyable<class_type>::value, "kir::bin::unpack_class_at() only accepts types that are trivially copyable!");
			static_assert(std::is_standard_layout<class_type>::value, "kir::bin::unpack_class_at() only accepts types with a standard layout!");
			static_assert(sizeof(class_type) > 1, "kir::bin::unpack_class_at() does not accept empty classes!");
			const size_t type_size = size_override == 0 ? sizeof(class_type) : size_override;
			if (offset + type_size > buffer.size()) return false;
			std::memcpy(&out, buffer.data() + offset, type_size);
			offset += type_size;
			return true;
		}
	}
}
#endif // KIR_EXCLUDE_BIN