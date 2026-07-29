#pragma once

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
	class bin {
	public:
		/**
		 * \brief Writes an integer into a buffer at a specific offset.
		 * The value is encoded in little-endian format.
		 * No resizing is performed; the buffer must already be large enough.
		 *
		 * \tparam IntType: Integral type to write.
		 *
		 * \param buffer: Destination byte buffer.
		 * \param offset: Position in buffer to write at.
		 * \param value: Integer value to encode.
		 *
		 * \return true if the value was written successfully, false if the buffer is too small.
		 */
		template <typename IntType>
		static bool pack_int_at(kir::bytes& buffer, const size_t offset, const IntType value) noexcept {
			static_assert(std::is_integral<IntType>::value, "kir::bin::pack_int_at only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "kir::bin::pack_int_at only supports types smaller than 0xFF!");
			if (offset + sizeof(IntType) > buffer.size()) return false;
			if constexpr (std::is_signed<IntType>::value) {
				using UIntType = typename std::make_unsigned<IntType>::type;
				const UIntType unsignedValue = static_cast<UIntType>(value);
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					buffer[offset + i] = static_cast<kir::byte>((unsignedValue >> (i * 8)) & 0xFF);
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					buffer[offset + i] = static_cast<kir::byte>((value >> (i * 8)) & 0xFF);
				}
			}
			return true;
		}

		/**
		 * \brief Writes an integer into a buffer and advances the offset.
		 * Acts like a streaming writer: after writing, the offset is incremented
		 * by sizeof(IntType).
		 *
		 * \tparam IntType Integral type to write.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param value: Integer value to encode.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename IntType>
		static bool pack_int_at(size_t& offset, kir::bytes& buffer, const IntType value) noexcept {
			if (!pack_int_at<IntType>(buffer, offset, value)) {
				return false;
			}
			offset += sizeof(IntType);
			return true;
		}

		/**
		 * \brief Appends an integer to the end of a byte buffer.
		 * The buffer is resized automatically if needed.
		 * The value is encoded in little-endian format.
		 *
		 * \tparam IntType: Integral type to write.
		 *
		 * \param buffer: Destination byte buffer (will grow).
		 * \param value: Integer value to encode.
		 *
		 * \return true if the value was successfully appended, false on allocation failure.
		 */
		template <typename IntType>
		static bool pack_int(kir::bytes& buffer, const IntType value) noexcept {
			static_assert(std::is_integral<IntType>::value, "kir::bin::pack_int only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "kir::bin::pack_int only supports types smaller than 0xFF!");
			try {
				buffer.reserve(buffer.size() + sizeof(IntType));
				if constexpr (std::is_signed<IntType>::value) {
					using UIntType = typename std::make_unsigned<IntType>::type;
					const UIntType unsignedValue = static_cast<UIntType>(value);
					for (uint8_t i = 0; i < sizeof(UIntType); ++i) {
						buffer.push_back(static_cast<kir::byte>((unsignedValue >> (i * 8)) & 0xFF));
					}
				}
				else {
					for (uint8_t i = 0; i < sizeof(IntType); ++i) {
						buffer.push_back(static_cast<kir::byte>((value >> (i * 8)) & 0xFF));
					}
				}
			}
			catch (...) { return false; }
			return true;
		}
	public:
		/**
		 * \brief Reads an integer from a buffer at a specific offset.
		 * The value is decoded using little-endian format.
		 *
		 * \tparam IntType Integral type to read.
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer to read from.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename IntType>
		static bool unpack_int_at(const kir::bytes& buffer, const size_t offset, IntType& out) noexcept {
			static_assert(std::is_integral<IntType>::value, "kir::bin::unpack_int_at only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "kir::bin::unpack_int_at only supports types smaller than 0xFF!");
			if (offset + sizeof(IntType) > buffer.size()) return false;
			out = IntType{};
			if constexpr (std::is_signed<IntType>::value) {
				using UIntType = typename std::make_unsigned<IntType>::type;
				for (uint8_t i = 0; i < sizeof(UIntType); ++i) {
					out |= static_cast<IntType>(static_cast<UIntType>(buffer[offset + i]) << (8 * i));
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					out |= static_cast<IntType>(buffer[offset + i]) << (8 * i);
				}
			}
			return true;
		}

		/**
		 * \brief Reads an integer from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * \tparam IntType: Integral type to read.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename IntType>
		static bool unpack_int_at(size_t& offset, const kir::bytes& buffer, IntType& out) noexcept {
			if (!unpack_int_at<IntType>(buffer, offset, out)) {
				return false;
			}
			offset += sizeof(IntType);
			return true;
		}

		/**
		 * \brief Reads an integer from a buffer and returns it.
		 * This is a convenience wrapper that does not use an output parameter.
		 *
		 * \tparam IntType: Integral type to read.
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 * \param outSuccess: Optional output flag indicating success or failure.
		 *
		 * \return Decoded integer value, or 0 on failure.
		 */
		template <typename IntType>
		[[nodiscard("kir::bin::unpack_int_at_r() is pointless without use of its return value.")]]
		static IntType unpack_int_at_r(const kir::bytes& buffer, const size_t offset, bool* outSuccess = nullptr) noexcept {
			IntType out = IntType{};
			if (!unpack_int_at<IntType>(buffer, offset, out)) {
				if (outSuccess) *outSuccess = false;
				return IntType{};
			}
			if (outSuccess) *outSuccess = true;
			return out;
		}

		/**
		 * \brief Reads an integer from a buffer, returns it, and advances the offset.
		 * This behaves like a streaming reader with return-style output.
		 *
		 * \tparam IntType: Integral type to read.
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param outSuccess: Optional output flag indicating success or failure.
		 *
		 * \return Decoded integer value, or 0 on failure.
		 */
		template <typename IntType>
		[[nodiscard("kir::bin::unpack_int_at_r() is pointless without use of its return value.")]]
		static IntType unpack_int_at_r(size_t& offset, const kir::bytes& buffer, bool* outSuccess = nullptr) noexcept {
			IntType out = IntType{};
			if (!unpack_int_at<IntType>(buffer, offset, out)) {
				if (outSuccess) *outSuccess = false;
				return IntType{};
			}
			offset += sizeof(IntType);
			if (outSuccess) *outSuccess = true;
			return out;
		}

		/**
		 * \brief Reads an integer from a buffer or throws on failure.
		 * If the buffer does not contain enough data, an exception is thrown.
		 *
		 * \tparam IntType: Integral type to read.
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 *
		 * \return Decoded integer value.
		 *
		 * \throws std::invalid_argument If the buffer is too small.
		 */
		template <typename IntType>
		[[nodiscard("kir::bin::unpack_int_at_e() is pointless without use of its return value.")]]
		static IntType unpack_int_at_e(const kir::bytes& buffer, const size_t offset) {
			static_assert(std::is_integral<IntType>::value, "kir::bin::unpack_int_at_e only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "kir::bin::unpack_int_at_e only supports types smaller than 0xFF!");
			if (offset + sizeof(IntType) > buffer.size()) throw std::invalid_argument("Buffer too small!");
			IntType out = IntType{};
			if constexpr (std::is_signed<IntType>::value) {
				using UIntType = typename std::make_unsigned<IntType>::type;
				for (uint8_t i = 0; i < sizeof(UIntType); ++i) {
					out |= static_cast<IntType>(static_cast<UIntType>(buffer[offset + i]) << (8 * i));
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					out |= static_cast<IntType>(buffer[offset + i]) << (8 * i);
				}
			}
			return out;
		}

		/**
		 * \brief Reads an integer, advances offset, or throws on failure.
		 * Streaming variant of the exception-based reader.
		 *
		 * \tparam IntType: Integral type to read.
		 *
		 * \param offset: Position in buffer (will be advanced).
		 * \param buffer: Source byte buffer.
		 *
		 * \return Decoded integer value.
		 *
		 * \throws std::invalid_argument If the buffer is too small.
		 */
		template <typename IntType>
		[[nodiscard("kir::bin::unpack_int_at_e() is pointless without use of its return value.")]]
		static IntType unpack_int_at_e(size_t& offset, const kir::bytes& buffer) {
			const IntType out = unpack_int_at_e<IntType>(buffer, offset);
			offset += sizeof(IntType);
			return out;
		}
	public:
		/**
		 * \brief Writes a floating-point value into a buffer at a specific offset.
		 * The raw binary representation of the value is copied into the buffer.
		 * No resizing is performed; the buffer must already be large enough.
		 *
		 * \tparam FloatType: Floating-point type to write (default: float).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param offset: Position in buffer to write at.
		 * \param value: Floating-point value to encode.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename FloatType = float>
		static bool pack_float_at(kir::bytes& buffer, const size_t offset, const FloatType value) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "kir::bin::pack_float_at only supports floating point types!");
			if (offset + sizeof(FloatType) > buffer.size()) return false;
			std::memcpy(&buffer[offset], &value, sizeof(FloatType));
			return true;
		}

		/**
		 * \brief Writes a floating-point value into a buffer and advances the offset.
		 * Acts like a streaming writer: after writing, the offset is incremented
		 * by sizeof(FloatType).
		 *
		 * \tparam FloatType: Floating-point type to write (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param value: Floating-point value to encode.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename FloatType = float>
		static bool pack_float_at(size_t& offset, kir::bytes& buffer, const FloatType value) noexcept {
			if (!pack_float_at<FloatType>(buffer, offset, value)) {
				return false;
			}
			buffer += sizeof(FloatType);
			return true;
		}

		/**
		 * \brief Appends a floating-point value to the end of a byte buffer.
		 * The buffer is resized automatically if needed.
		 * The raw binary representation of the value is appended.
		 *
		 * \tparam FloatType: Floating-point type to write (default: float).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param value: Floating-point value to encode.
		 *
		 * \return true if successful, false on allocation failure.
		 */
		template <typename FloatType = float>
		static bool pack_float(kir::bytes& buffer, const FloatType value) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "kir::bin::pack_float only supports floating point types!");
			const size_t oldSize = buffer.size();
			try {
				buffer.resize(oldSize + sizeof(FloatType));
				std::memcpy(&buffer[oldSize], &value, sizeof(FloatType));
			}
			catch (...) { return false; }
			return true;
		}
	public:
		/**
		 * \brief Reads a floating-point value from a buffer at a specific offset.
		 * Reads the raw binary representation from the buffer into the output value.
		 *
		 * \tparam FloatType: Floating-point type to read (default: float).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer to read from.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename FloatType = float>
		static bool unpack_float_at(const kir::bytes& buffer, const size_t offset, FloatType& out) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "kir::bin::unpack_float_at only supports floating point types!");
			if (offset + sizeof(FloatType) > buffer.size()) return false;
			std::memcpy(&out, buffer.data() + offset, sizeof(FloatType));
			return true;
		}

		/**
		 * \brief Reads a floating-point value from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * \tparam FloatType: Floating-point type to read (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output variable for decoded value.
		 *
		 * \return true if successful, false if the buffer is too small.
		 */
		template <typename FloatType = float>
		static bool unpack_float_at(size_t& offset, const kir::bytes& buffer, FloatType& out) noexcept {
			if (!unpack_float_at<FloatType>(buffer, offset, out)) {
				return false;
			}
			offset += sizeof(FloatType);
			return true;
		}

		/**
		 * \brief Reads a floating-point value from a buffer and returns it.
		 * This is a convenience wrapper that does not use an output parameter.
		 *
		 * \tparam FloatType: Floating-point type to read (default: float).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 * \param outSuccess: Optional output flag indicating success or failure.
		 *
		 * \return Decoded value, or 0.0f on failure.
		 */
		template <typename FloatType = float>
		[[nodiscard("kir::bin::unpack_float_at_r() is pointless without use of its return value.")]]
		static FloatType unpack_float_at_r(const kir::bytes& buffer, const size_t offset, bool* outSuccess = nullptr) noexcept {
			FloatType out = FloatType{};
			if (!unpack_float_at<FloatType>(buffer, offset, out)) {
				if (outSuccess) *outSuccess = false;
				return FloatType{};
			}
			if (outSuccess) *outSuccess = true;
			return out;
		}

		/**
		 * \brief Reads a floating-point value, returns it, and advances the offset.
		 * This behaves like a streaming reader with return-style output.
		 *
		 * \tparam FloatType: Floating-point type to read (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param outSuccess: Optional output flag indicating success or failure.
		 *
		 * \return Decoded value, or 0.0f on failure.
		 */
		template <typename FloatType = float>
		[[nodiscard("kir::bin::unpack_float_at_r() is pointless without use of its return value.")]]
		static FloatType unpack_float_at_r(size_t& offset, const kir::bytes& buffer, bool* outSuccess = nullptr) noexcept {
			FloatType out = FloatType{};
			if (!unpack_float_at<FloatType>(buffer, offset, out)) {
				if (outSuccess) *outSuccess = false;
				return FloatType{};
			}
			offset += sizeof(FloatType);
			if (outSuccess) *outSuccess = true;
			return out;
		}

		/**
		 * \brief Reads a floating-point value from a buffer or throws on failure.
		 * If the buffer does not contain enough data, an exception is thrown.
		 *
		 * \tparam FloatType: Floating-point type to read (default: float).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer.
		 *
		 * \return Decoded floating-point value.
		 *
		 * \throws std::invalid_argument: Buffer does not contain enough data.
		 */
		template <typename FloatType = float>
		[[nodiscard("kir::bin::unpack_float_at_e() is pointless without use of its return value.")]]
		static FloatType unpack_float_at_e(const kir::bytes& buffer, const size_t offset) {
			static_assert(std::is_floating_point<FloatType>::value, "kir::bin::unpack_float_at_e only supports floating point types!");
			if (offset + sizeof(FloatType) > buffer.size()) throw std::invalid_argument("Buffer too small!");
			FloatType out = FloatType{};
			std::memcpy(&out, buffer.data() + offset, sizeof(FloatType));
			return out;
		}

		/**
		 * \brief Reads a floating-point value, advances the offset, or throws on failure.
		 * Streaming variant of the exception-based reader.
		 *
		 * \tparam FloatType: Floating-point type to read (default: float).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 *
		 * \return Decoded floating-point value.
		 *
		 * \throws std::invalid_argument: Buffer does not contain enough data.
		 */
		template <typename FloatType = float>
		[[nodiscard("kir::bin::unpack_float_at_e() is pointless without use of its return value.")]]
		static FloatType unpack_float_at_e(size_t& offset, const kir::bytes& buffer) {
			const FloatType out = unpack_float_at_e<FloatType>(buffer, offset);
			offset += sizeof(FloatType);
			return out;
		}
	public:
		/**
		 * \brief Writes a string into a buffer at a specific offset.
		 * The string is stored as a length value followed by the raw string data.
		 * No resizing is performed; the buffer must already be large enough.
		 *
		 * \tparam SizeType: Unsigned integral type used for storing string length (default: uint16_t).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param offset: Position in buffer to write at.
		 * \param str: String to encode.
		 *
		 * \return true if successful, false if the buffer is too small
		 * or the string exceeds the maximum representable length.
		 */
		template <typename SizeType = uint16_t>
		static bool pack_str_at(kir::bytes& buffer, const size_t offset, const std::string& str) noexcept {
			static_assert(std::is_integral<SizeType>::value, "kir::bin::pack_str_at only supports unsigned integral types!");
			static_assert(!std::is_signed<SizeType>::value, "kir::bin::pack_str_at only supports unsigned integral types!");
			if ((std::numeric_limits<SizeType>::max)() < str.size()) return false;
			const SizeType len = static_cast<SizeType>(str.size());
			if (offset + sizeof(SizeType) + len > buffer.size()) return false;
			std::memcpy(buffer.data() + offset, &len, sizeof(SizeType));
			std::memcpy(buffer.data() + offset + sizeof(SizeType), str.data(), len);
			return true;
		}

		/**
		 * \brief Writes a string into a buffer and advances the offset.
		 * Acts like a streaming writer: after writing, the offset is incremented
		 * by the size of the stored length and string data.
		 *
		 * \tparam SizeType: Unsigned integral type used for storing string length (default: uint16_t).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Destination byte buffer.
		 * \param str: String to encode.
		 *
		 * \return true if successful, false if the buffer is too small
		 * or the string exceeds the maximum representable length.
		 */
		template <typename SizeType = uint16_t>
		static bool pack_str_at(size_t& offset, kir::bytes& buffer, const std::string& str) noexcept {
			if (!pack_str_at<SizeType>(buffer, offset, str)) {
				return false;
			}
			offset += sizeof(SizeType);
			return true;
		}

		/**
		 * \brief Appends a string to the end of a byte buffer.
		 * The string is stored as a length value followed by the raw string data.
		 * The buffer is resized automatically if needed.
		 *
		 * \tparam SizeType: Unsigned integral type used for storing string length (default: uint16_t).
		 *
		 * \param buffer: Destination byte buffer.
		 * \param str: String to encode.
		 *
		 * \return true if successful, false if allocation fails
		 * or the string exceeds the maximum representable length.
		 */
		template <typename SizeType = uint16_t>
		static bool pack_str(kir::bytes& buffer, const std::string& str) noexcept {
			static_assert(std::is_integral<SizeType>::value, "kir::bin::pack_str only supports unsigned integral types!");
			static_assert(!std::is_signed<SizeType>::value, "kir::bin::pack_str only supports unsigned integral types!");
			if ((std::numeric_limits<SizeType>::max)() < str.size()) return false;
			const SizeType len = static_cast<SizeType>(str.size());
			const size_t bufferLen = buffer.size();
			try { buffer.resize(bufferLen + sizeof(SizeType) + len); }
			catch (...) { return false; }
			std::memcpy(buffer.data() + bufferLen, &len, sizeof(SizeType));
			std::memcpy(buffer.data() + bufferLen + sizeof(SizeType), str.data(), len);
			return true;
		}
	public:
		/**
		 * \brief Reads a string from a buffer at a specific offset.
		 * Expects the string to be stored as a length value followed by raw string data.
		 *
		 * \tparam SizeType: Unsigned integral type used for reading string length (default: uint16_t).
		 *
		 * \param buffer: Source byte buffer.
		 * \param offset: Position in buffer to read from.
		 * \param out: Output string for decoded data.
		 *
		 * \return true if successful, false if the buffer does not contain
		 * enough data or string allocation fails.
		 */
		template <typename SizeType = uint16_t>
		static bool unpack_str_at(const kir::bytes& buffer, const size_t offset, std::string& out) noexcept {
			static_assert(std::is_integral<SizeType>::value, "kir::bin::unpack_str_at only supports integral types!");
			static_assert(!std::is_signed<SizeType>::value, "kir::bin::unpack_str_at only supports unsigned types!");
			if (offset + sizeof(SizeType) > buffer.size()) return false;
			SizeType len = SizeType{};
			std::memcpy(&len, buffer.data() + offset, sizeof(SizeType));
			if (offset + sizeof(SizeType) + len > buffer.size()) return false;
			if (out.size() != len) out.resize(len);
			try { out.assign(reinterpret_cast<const char*>(buffer.data() + offset + sizeof(SizeType)), len); }
			catch (...) { return false; }
			return true;
		}

		/**
		 * \brief Reads a string from a buffer and advances the offset.
		 * Acts like a streaming reader.
		 *
		 * \tparam SizeType: Unsigned integral type used for reading string length (default: uint16_t).
		 *
		 * \param offset: Position in buffer (will be advanced on success).
		 * \param buffer: Source byte buffer.
		 * \param out: Output string for decoded data.
		 *
		 * \return true if successful, false if the buffer does not contain
		 * enough data or string allocation fails.
		 */
		template <typename SizeType = uint16_t>
		static bool unpack_str_at(size_t& offset, const kir::bytes& buffer, std::string& out) noexcept {
			if (!unpack_str_at<SizeType>(buffer, offset, out)) {
				return false;
			}
			offset += sizeof(SizeType) + out.size();
			return true;
		}
	};
}
