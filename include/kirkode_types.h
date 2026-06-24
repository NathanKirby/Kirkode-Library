#pragma once

#include <cstdint>
#include <vector>
#include <type_traits>

namespace kir {
	/**
	 * \brief Alias for a single raw byte.
	 *
	 * Represents an 8-bit unsigned value used for low-level binary operations,
	 * such as serialization, memory manipulation, and network packet construction.
	 */
	typedef std::uint8_t byte;

	/**
	 * \brief Dynamic byte buffer.
	 *
	 * Represents a contiguous sequence of raw bytes.
	 * Commonly used as the primary buffer type for binary serialization
	 * and deserialization routines in this library.
	 *
	 * Typical usage includes:
	 * 1: Encoding integers and floating-point values.
	 * 2: Building network packets (e.g., UDP payloads).
	 * 3: Reading/writing binary file data.
	 */
	typedef std::vector<uint8_t> bytes;

	/**
	 * \brief Millisecond-based timestamp type.
	 *
	 * Represents time values in milliseconds since an implementation-defined epoch.
	 * Used by timing utilities such as stopwatches and clocks.
	 *
	 * This type is intended for:
	 * 1: Measuring elapsed time.
	 * 2: Timestamping events.
	 * 3: Performance timing and profiling.
	 */
	typedef std::uint64_t time;
}

namespace kir {
	/**
	 * \brief Bit index enumeration for flag_poll bitfields.
	 *
	 * Represents a fixed set of bit positions (0–63) used to manipulate
	 * flags inside a PollType bitmask.
	 *
	 * Each value corresponds to a single bit index:
	 *
	 * - FLAG_0  = bit 0
	 * - FLAG_1  = bit 1
	 * - ...
	 * - FLAG_63 = bit 63
	 *
	 * This enum is intended to be used with kir::flag_poll for setting,
	 * clearing, and checking individual bits in a compact integer mask.
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
	 * Provides a lightweight wrapper around an unsigned integral type
	 * to manage up to 64 boolean flags using bitwise operations.
	 * Each flag is addressed using flag_bit, which represents a bit index.
	 *
	 * \tparam PollType: Unsigned integral type used as storage (default: uint16_t).
	 */
	template <typename PollType = uint16_t>
	class flag_poll {
		static_assert(std::is_integral_v<PollType>, "Flag type must be integral!");
		static_assert(!std::is_signed_v<PollType>, "Flag type must be unsigned!");
	private:
		PollType poll;
	public:
		/**
		 * \brief Constructs an empty flag poll with all flags cleared.
		 */
		flag_poll() noexcept : poll(0) {}

		/**
		 * \brief Constructs a flag poll with an initial value.
		 *
		 * \param f: Initial bitmask value.
		 */
		flag_poll(const PollType f) noexcept : poll(f) {}
	public:
		/**
		 * \brief Clears all flags.
		 * Resets the internal bitmask to zero.
		 */
		void clear_all() noexcept { poll = 0; }

		/**
		 * \brief Sets a specific flag bit.
		 *
		 * Activates the bit corresponding to the provided flag_bit index.
		 *
		 * \param f: Flag bit to set.
		 *
		 * \return true if the flag was set successfully, false if the bit
		 * index exceeds the size of PollType.
		 */
		bool set_flag(const flag_bit f) noexcept {
			const uint8_t bit = static_cast<uint8_t>(f);
			if (bit >= sizeof(PollType) * 8) return false;
			poll |= (PollType(1) << bit);
			return true;
		}

		/**
		 * \brief Clears a specific flag bit.
		 *
		 * Deactivates the bit corresponding to the provided flag_bit index.
		 *
		 * \param f: Flag bit to clear.
		 *
		 * \return true if the flag was cleared successfully, false if the bit
		 * index exceeds the size of PollType.
		 */
		bool clear_flag(const flag_bit f) noexcept {
			const uint8_t bit = static_cast<uint8_t>(f);
			if (bit >= sizeof(PollType) * 8) return false;
			poll &= ~(PollType(1) << bit);
			return true;
		}

		/**
		 * \brief Checks whether a flag bit is set.
		 *
		 * \param f: Flag bit to check.
		 *
		 * \return true if the specified flag is active, false otherwise.
		 */
		[[nodiscard("kir::flag_pol::flag_set() is a getter.")]]
		bool flag_set(const flag_bit f) const noexcept { return poll & (PollType(1) << static_cast<uint8_t>(f)); }

		/**
		 * \brief Retrieves the raw bitmask value.
		 *
		 * \return Current flag bitmask.
		 */
		[[nodiscard("kir::flag_pol::get() is a getter.")]]
		PollType get() const noexcept { return poll; }
	};
}