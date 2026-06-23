#pragma once

#include "kirkode_types.h"

#include <string>
#include <cstring> // std::memcpy
#include <type_traits> // std::is_integral
#include <limits> // std::numeric_limits

#ifdef max
#undef max // Ensures std::numeric_limits<T>::max() is available.
#endif

namespace kir {
	class bin {
	public:
		/**
		* Packs an integral value into a byte buffer at a specific offset in little-endian order.
		* Both signed and unsigned types are handled safely.
		*
		* \param buffer: Byte buffer to write to. Must have enough space to pack 'value' at 'offset.'
		* \param offset: Position in the byte buffer to write to. Offset is adjusted after packing.
		* \param value: Integral value to write into byte buffer.
		* \tparam IntType: Type of integer to pack. Must be an integral type.
		* \return True if successfully packed integer to byte buffer, and false on error.
		*/
		template <typename IntType>
		static bool pack_int_at(kir::bytes& buffer, size_t& offset, IntType value) noexcept {
			static_assert(std::is_integral<IntType>::value, "pack_int_at only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "pack_int_at only supports types smaller than 0xFF!");
			if (offset + sizeof(IntType) > buffer.size()) return false;
			if constexpr (std::is_signed<IntType>::value) {
				using UIntType = std::make_unsigned_t<IntType>;
				UIntType unsignedValue = static_cast<UIntType>(value);
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					buffer[offset + i] = static_cast<kir::byte>(unsignedValue & 0xFF);
					unsignedValue >>= 8;
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					buffer[offset + i] = static_cast<kir::byte>(value & 0xFF);
					value >>= 8;
				}
			}
			offset += sizeof(IntType);
			return true;
		}

		/**
		* Packs a floating point value into a byte buffer at a specific offset.
		*
		* \param buffer: Byte buffer to write to. Must have enough space to pack 'value' at 'offset.'
		* \param offset: Position in the byte buffer to write to. Offset is adjusted after packing.
		* \param value: Floating point value to write into byte buffer.
		* \tparam FloatType: Type of float to pack. Must be a floating point type.
		* \return True if successfully packed float to byte buffer, and false on error.
		*/
		template <typename FloatType = float>
		static bool pack_float_at(kir::bytes& buffer, size_t& offset, FloatType value) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "pack_float_at only supports floating point types!");
			if (offset + sizeof(FloatType) > buffer.size()) return false;
			std::memcpy(&buffer[offset], &value, sizeof(FloatType));
			offset += sizeof(FloatType);
			return true;
		}

		/**
		* Appends an integral value to a byte buffer in little-endian order.
		* Both signed and unsigned types are handled safely.
		* Prefer 'pack_int_at' for multiple calls.
		*
		* \param buffer: Byte buffer to append integer to.
		* \param value: Integral value to append to byte buffer.
		* \tparam IntType: Type of integer to append. Must be an integral type.
		* \return True if successfully packed integer to byte buffer, and false on error.
		*/
		template <typename IntType>
		static bool pack_int(kir::bytes& buffer, IntType value) noexcept {
			static_assert(std::is_integral<IntType>::value, "pack_int only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "pack_int only supports types smaller than 0xFF!");
			try {
				buffer.reserve(buffer.size() + sizeof(IntType));
				if constexpr (std::is_signed<IntType>::value) {
					using UIntType = std::make_unsigned_t<IntType>;
					UIntType unsignedValue = static_cast<UIntType>(value);
					for (uint8_t i = 0; i < sizeof(UIntType); ++i) {
						buffer.push_back(static_cast<kir::byte>(unsignedValue & 0xFF));
						unsignedValue >>= 8;
					}
				}
				else {
					for (uint8_t i = 0; i < sizeof(IntType); ++i) {
						buffer.push_back(static_cast<kir::byte>(value & 0xFF));
						value >>= 8;
					}
				}
			}
			catch (...) { return false; }
			return true;
		}

		/**
		* Appends a floating point value to a byte buffer.
		* Prefer 'pack_float_at' for multiple calls.
		*
		* \param buffer: Byte buffer to append float to.
		* \param value: Floating point value to append to byte buffer.
		* \tparam FloatType: Type of float to append. Must be a floating point type.
		* \return True if successfully packed float to byte buffer, and false on error.
		*/
		template <typename FloatType = float>
		static bool pack_float(kir::bytes& buffer, FloatType value) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "pack_float only supports floating point types!");
			const size_t oldSize = buffer.size();
			try {
				buffer.resize(oldSize + sizeof(FloatType));
				std::memcpy(&buffer[oldSize], &value, sizeof(FloatType));
			}
			catch (...) { return false; }
			return true;
		}

		/**
		* Unpacks an integral value from a byte buffer at a specific referenced offset in little-endian order.
		* Both signed and unsigned types are handled safely.
		*
		* \param buffer: Byte buffer to unpack integer from.
		* \param offset: Position in the byte buffer to unpack integer from. Offset is adjusted after unpacking.
		* \param out: Unpacked integer.
		* \tparam IntType: Type of integer to unpack. Must be an integral type.
		* \return True if successfully unpacked integer from byte buffer, and false on error.
		*/
		template <typename IntType>
		static bool unpack_int_at(const kir::bytes& buffer, size_t& offset, IntType& out) noexcept {
			static_assert(std::is_integral<IntType>::value, "unpack_int_at only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "unpack_int_at only supports types smaller than 0xFF!");
			if (offset + sizeof(IntType) > buffer.size()) return false;
			out = 0;
			if constexpr (std::is_signed<IntType>::value) {
				using UIntType = std::make_unsigned_t<IntType>;
				for (uint8_t i = 0; i < sizeof(UIntType); ++i) {
					out |= static_cast<IntType>(static_cast<UIntType>(buffer[offset + i]) << (8 * i));
				}
			}
			else {
				for (uint8_t i = 0; i < sizeof(IntType); ++i) {
					out |= static_cast<IntType>(buffer[offset + i]) << (8 * i);
				}
			}
			offset += sizeof(IntType);
			return true;
		}

		/**
		* Unpacks an integral value from a byte buffer at a specific offset in little-endian order.
		* Both signed and unsigned types are handled safely.
		*
		* \param buffer: Byte buffer to unpack integer from.
		* \param offset: Position in the byte buffer to unpack integer from. Offset is not adjusted after unpacking.
		* \tparam IntType: Type of integer to unpack. Must be an integral type.
		* \return Unpacked int of specified type.
		*/
		template <typename IntType>
		static IntType unpack_int_at_r(const kir::bytes& buffer, const size_t offset) noexcept {
			static_assert(std::is_integral<IntType>::value, "unpack_int_at only supports integral types!");
			static_assert(sizeof(IntType) < 0xFF, "unpack_int_at only supports types smaller than 0xFF!");
			if (offset + sizeof(IntType) > buffer.size()) return 0;
			IntType out = 0;
			if constexpr (std::is_signed<IntType>::value) {
				using UIntType = std::make_unsigned_t<IntType>;
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
		* Unpacks a floating point value from a byte buffer at a specific offset.
		*
		* \param buffer: Byte buffer to unpack float from.
		* \param offset: Position in the byte buffer to unpack float from. Offset is adjusted after unpacking.
		* \param out: Unpacked float.
		* \tparam FloatType: Type of float to unpack. Must be a floating point type.
		* \return True if successfully unpacked float from byte buffer, and false on error.
		*/
		template <typename FloatType = float>
		static bool unpack_float_at(const kir::bytes& buffer, size_t& offset, FloatType& out) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "unpack_float_at only supports floating point types!");
			if (offset + sizeof(FloatType) > buffer.size()) return false;
			std::memcpy(&out, buffer.data() + offset, sizeof(FloatType));
			offset += sizeof(FloatType);
			return true;
		}

		/**
		* Packs a string into a byte buffer at a specific offset.
		*
		* \param buffer: Byte buffer to pack string to. Must have enough space to pack 'string' at 'offset.'
		* \param offset: Position in the byte buffer to pack string to. Offset is adjusted after unpacking.
		* \param string: String value to pack to byte buffer.
		* \fparam SizeType: Integral type to use for packing the length of 'string.'
		* \return True if successfully packed string to byte buffer, and false on error.
		*/
		template <typename SizeType = uint16_t>
		static bool pack_string_at(kir::bytes& buffer, size_t& offset, const std::string& string) noexcept {
			static_assert(std::is_integral<SizeType>::value, "pack_string_at only supports integral types!");
			static_assert(!std::is_signed<SizeType>::value, "pack_string_at only supports unsigned types!");
			if (std::numeric_limits<SizeType>::max() < string.size()) return false;
			const SizeType length = static_cast<SizeType>(string.size());
			if (offset + sizeof(SizeType) + length > buffer.size()) return false;
			std::memcpy(buffer.data() + offset, &length, sizeof(SizeType));
			std::memcpy(buffer.data() + offset + sizeof(SizeType), string.data(), length);
			offset += sizeof(SizeType) + length;
			return true;
		}

		/**
		* Unpacks a string from a byte buffer at a specific offset.
		*
		* \param buffer: Byte buffer to unpack string from.
		* \param offset: Position in the byte buffer to unpack string from. Offset is adjusted after unpacking.
		* \param out: Unpacked string.
		* \fparam SizeType: Integral type to unpack the length of the string.
		* \return True if successfully unpacked string from byte buffer, and false on error.
		*/
		template <typename SizeType = uint16_t>
		static bool unpack_string_at(const kir::bytes& buffer, size_t& offset, std::string& out) noexcept {
			static_assert(std::is_integral<SizeType>::value, "unpack_string_at only supports integral types!");
			static_assert(!std::is_signed<SizeType>::value, "unpack_string_at only supports unsigned types!");
			if (offset + sizeof(SizeType) > buffer.size()) return false;
			SizeType length = 0;
			std::memcpy(&length, buffer.data() + offset, sizeof(SizeType));
			if (offset + sizeof(SizeType) + length > buffer.size()) return false;
			if (out.size() != length) out.resize(length);
			out.assign(reinterpret_cast<const char*>(buffer.data() + offset + sizeof(SizeType)), length);
			offset += sizeof(SizeType) + length;
			return true;
		}
	};
}