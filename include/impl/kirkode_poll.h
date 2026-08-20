#pragma once
#ifndef KIR_EXCLUDE_POLL
#include "kirkode_types.h"

#include <type_traits>
#include <cstdint>

namespace kir {
	/**
	 * \brief Bit index enumeration for flag_poll bitfields.
	 *
	 * Represents a fixed set of bit positions (0-63) used to manipulate
	 * flags inside a poll_type bitmask.
	 */
	enum class flag_bit : uint8_t {
		FLAG_0, FLAG_1, FLAG_2, FLAG_3, FLAG_4, FLAG_5, FLAG_6, FLAG_7,
		FLAG_8, FLAG_9, FLAG_10, FLAG_11, FLAG_12, FLAG_13, FLAG_14, FLAG_15,
		FLAG_16, FLAG_17, FLAG_18, FLAG_19, FLAG_20, FLAG_21, FLAG_22, FLAG_23,
		FLAG_24, FLAG_25, FLAG_26, FLAG_27, FLAG_28, FLAG_29, FLAG_30, FLAG_31,
		FLAG_32, FLAG_33, FLAG_34, FLAG_35, FLAG_36, FLAG_37, FLAG_38, FLAG_39,
		FLAG_40, FLAG_41, FLAG_42, FLAG_43, FLAG_44, FLAG_45, FLAG_46, FLAG_47,
		FLAG_48, FLAG_49, FLAG_50, FLAG_51, FLAG_52, FLAG_53, FLAG_54, FLAG_55,
		FLAG_56, FLAG_57, FLAG_58, FLAG_59, FLAG_60, FLAG_61, FLAG_62, FLAG_63
	};

	/**
	 * \brief Fixed-size bitflag container utility.
	 * Provides a lightweight wrapper around an 8-byte storage array
	 * to manage up to 64 boolean flags using bitwise operations.
	 * Each flag is addressed using flag_bit, which represents a bit index.
	 */
	class flag_poll {
	private:
		// Byte array for holding flags.
		kir::byte _fields[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	public:
		/**
		 * \brief Constructs an empty flag poll with all flags cleared.
		 */
		flag_poll() noexcept;

		/**
		 * \brief Constructs a flag poll with an initial value.
		 *
		 * \param value: Initial 64-bit bitmask value.
		 */
		flag_poll(const uint64_t value) noexcept;

		/**
		 * \brief Constructs a flag poll from a byte buffer.
		 *
		 * Initializes the flag poll using the provided byte buffer.
		 *
		 * \param buffer: Byte buffer containing the initial flag data.
		 */
		flag_poll(const kir::bytes buffer) noexcept;
	public:
		/**
		 * \brief Sets a specific flag bit.
		 *
		 * Activates the bit corresponding to the provided flag_bit index.
		 *
		 * \param flag: Flag bit to set.
		 */
		void set_flag(const flag_bit flag) noexcept;

		/**
		 * \brief Clears a specific flag bit.
		 *
		 * Deactivates the bit corresponding to the provided flag_bit index.
		 *
		 * \param flag: Flag bit to clear.
		 */
		void clear_flag(const flag_bit flag) noexcept;

		/**
		 * \brief Clears all flags.
		 *
		 * Resets the internal bitmask to zero.
		 */
		void clear_all() noexcept;

		/**
		 * \brief Sets the raw bitmask value.
		 *
		 * Replaces the current flag state with the provided 64-bit value.
		 *
		 * \param value: 64-bit bitmask value to store.
		 */
		void set_value(const uint64_t value) noexcept;
	public:
		/**
		 * \brief Checks whether a flag bit is set.
		 *
		 * \param flag: Flag bit to check.
		 *
		 * \return true if the specified flag is active, false otherwise.
		 */
		[[nodiscard("kir::flag_poll::flag_set() is a getter.")]]
		bool flag_set(const flag_bit flag) const noexcept;
		/**
		 * \brief Checks whether any flag is set.
		 *
		 * \return true if at least one flag is active, false if all flags
		 * are cleared.
		 */
		[[nodiscard("kir::flag_poll::any_flag_set() is a getter.")]]
		bool any_flag_set() const noexcept;

		/**
		 * \brief Retrieves the size of the flag storage.
		 *
		 * \return Number of bytes used by the flag poll.
		 */
		[[nodiscard("kir::flag_poll::get_size() is a getter.")]]
		kir::size get_size() const noexcept;

		/**
		 * \brief Retrieves the raw 64-bit bitmask value.
		 *
		 * \return Current flag bitmask.
		 */
		[[nodiscard("kir::flag_poll::get_value() is a getter.")]]
		uint64_t get_value() const noexcept;

		/**
		 * \brief Converts the flag poll to a byte buffer.
		 *
		 * \return Byte buffer containing the current flag data.
		 */
		[[nodiscard("kir::flag_poll::to_bytes() is a getter.")]]
		kir::bytes to_bytes() const noexcept;
	};
}
#endif // KIR_EXCLUDE_POLL