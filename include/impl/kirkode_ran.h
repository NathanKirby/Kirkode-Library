#pragma once
#ifndef KIR_EXCLUDE_RAN
#include "kirkode_types.h"

#include <random> // std::random_device, std::mt19937, std::uniform_int_distribution, std::uniform_real_distribution
#include <type_traits> // std::is_integral
#include <limits> // std::numeric_limits

namespace kir {
	/**
	 * \brief Static random number generation utility based on Mersenne Twister.
	 *
	 * Provides thread-shared pseudo-random generation for integers, floating-point
	 * values, and raw byte sequences.
	 *
	 * The generator is seeded once using std::random_device and reused globally.
	 */
	namespace ran {
		/**
		* \brief Gets the static global Mersenne Twiser random number generator.
		*
		* \return std::mt19937 random generator.
		*/
		[[nodiscard("kir::ran::get_engine() is a getter.")]]
		std::mt19937& get_engine() noexcept;

		/**
		* \brief Generates a random integral value spanning the full range of the specified integral type.
		*
		* \tparam int_type: Integral type used to define the range of possible values.
		* uint32_t by default.
		*
		* \return A randomly generated value of type int_type within the inclusive range
		* [std::numeric_limits<int_type>::min(), std::numeric_limits<int_type>::max()].
		*/
		template<typename int_type = uint32_t>
		[[nodiscard("kir::ran::random_int() is useless without use of its return value.")]]
		static int_type random_int() noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::ran::random_int() only supports integral types!");
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				std::uniform_int_distribution<int64_t> dist(
					(std::numeric_limits<int_type>::min)(),
					(std::numeric_limits<int_type>::max)()
				);
				return static_cast<int_type>(dist(get_engine()));
			}
			else {
				std::uniform_int_distribution<uint64_t> dist(
					0,
					(std::numeric_limits<int_type>::max)()
				);
				return static_cast<int_type>(dist(get_engine()));
			}
		}

		/**
		* \brief Generates a random integral value within a range starting from the minimum representable value
		* of the specified type up to a user-defined maximum bound.
		*
		* \tparam int_type: Integral type used to define the range of possible values.
		* uint32_t by default.
		*
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type int_type within the inclusive range
		* [std::numeric_limits<int_type>::min(), max].
		*/
		template<typename int_type = uint32_t>
		[[nodiscard("kir::ran::random_int() is useless without use of its return value.")]]
		static int_type random_int(const int_type max) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::ran::random_int() only supports integral types!");
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				std::uniform_int_distribution<int64_t> dist(
					(std::numeric_limits<int_type>::min)(),
					max
				);
				return static_cast<int_type>(dist(get_engine()));
			}
			else {
				std::uniform_int_distribution<uint64_t> dist(
					0,
					max
				);
				return static_cast<int_type>(dist(get_engine()));
			}
		}

		/**
		* \brief Generates a random integral value within a user-specified inclusive range.
		*
		* \tparam int_type: Integral type used to define the range of possible values.
		*
		* \param min: Lower inclusive bound of the random range.
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type int_type within the inclusive range [min, max].
		*/
		template<typename int_type = uint32_t>
		[[nodiscard("kir::ran::random_int() is useless without use of its return value.")]]
		static int_type random_int(const int_type min, const int_type max) noexcept {
			static_assert(std::is_integral<int_type>::value, "kir::ran::random_int() only supports integral types!");
#if KIR_CPP_STD < 201703L
			if (std::is_signed<int_type>::value) {
#else
			if constexpr (std::is_signed<int_type>::value) {
#endif
				std::uniform_int_distribution<int64_t> dist(min, max);
				return static_cast<int_type>(dist(get_engine()));
			}
			else {
				std::uniform_int_distribution<uint64_t> dist(min, max);
				return static_cast<int_type>(dist(get_engine()));
			}
		}

		/**
		* \brief Generates a random floating point spanning the full range of the specified float type.
		*
		* \tparam float_type: Float type used to define the range of possible values.
		* float by default.
		*
		* \return A randomly generated value of type float_type within the inclusive range
		* [std::numeric_limits<float_type>::min(), std::numeric_limits<float_type>::max()].
		*/
		template<typename float_type = float>
		[[nodiscard("kir::ran::random_float() is useless without use of its return value.")]]
		static float_type random_float() noexcept {
			static_assert(std::is_floating_point<float_type>::value, "kir::ran::random_float() only supports floating point types!");
			std::uniform_real_distribution<double> dist(
				(std::numeric_limits<float_type>::min)(),
				(std::numeric_limits<float_type>::max)()
			);
			return static_cast<float_type>(dist(get_engine()));
		}

		/**
		* \brief Generates a random floating point within a range starting from the minimum representable value
		* of the specified type up to a user-defined maximum bound.
		*
		* \tparam float_type: Float type used to define the range of possible values.
		* float by default.
		*
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type float_type within the inclusive range
		* [std::numeric_limits<float_type>::min(), max].
		*/
		template<typename float_type = float>
		[[nodiscard("kir::ran::random_float() is useless without use of its return value.")]]
		static float_type random_float(const float_type max) noexcept {
			static_assert(std::is_floating_point<float_type>::value, "kir::ran::random_float() only supports floating point types!");
			std::uniform_real_distribution<double> dist(
				(std::numeric_limits<float_type>::min)(),
				max
			);
			return static_cast<float_type>(dist(get_engine()));
		}

		/**
		* \brief Generates a random floating point within a user-specified inclusive range.
		*
		* \tparam float_type: Float type used to define the range of possible values.
		* float by default.
		*
		* \param min: Lower inclusive bound of the random range.
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type float_type within the inclusive range [min, max].
		*/
		template<typename float_type = float>
		[[nodiscard("kir::ran::random_float() is useless without use of its return value.")]]
		static float_type random_float(const float_type min, const float_type max) noexcept {
			static_assert(std::is_floating_point<float_type>::value, "kir::ran::random_float() only supports floating point types!");
			std::uniform_real_distribution<double> dist(min, max);
			return static_cast<float_type>(dist(get_engine()));
		}

		/**
		* \brief Generates a hash of random bytes.
		*
		* \param len: Length of random hash.

		* \return A randomly generated hash.
		*/
		[[nodiscard("kir::ran::random_bytes() is useless without use of its return value.")]]
		kir::bytes random_bytes(const size_t len) noexcept;
	}
}
#endif // KIR_EXCLUDE_RAN