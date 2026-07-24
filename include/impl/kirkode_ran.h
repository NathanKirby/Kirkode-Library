#pragma once

#include "kirkode_types.h"

#include <random> // std::random_device, std::mt19937, std::uniform_int_distribution, std::uniform_real_distribution
#include <type_traits> // std::is_integral
#include <limits> // std::numeric_limits

namespace kir {
	/**
	 * \class ran
	 * \brief Static random number generation utility based on Mersenne Twister.
	 *
	 * Provides thread-shared pseudo-random generation for integers, floating-point
	 * values, and raw byte sequences.
	 *
	 * The generator is seeded once using std::random_device and reused globally.
	 */
	class ran {
	private:
		inline static std::random_device rd;
		inline static std::mt19937 engine = std::mt19937(rd());
	public:
		/**
		* \brief Generates a random integral value spanning the full range of the specified integral type.
		* 
		* \tparam IntType: Integral type used to define the range of possible values.
		* uint32_t by default.
		* 
		* \return A randomly generated value of type IntType within the inclusive range
		* [std::numeric_limits<IntType>::min(), std::numeric_limits<IntType>::max()].
		*/
		template<typename IntType = uint32_t>
		[[nodiscard("kir::ran::random_int() is useless without use of its return value.")]]
		static IntType random_int() noexcept {
			static_assert(std::is_integral<IntType>::value, "random_int only supports integral types!");
			if constexpr (std::is_signed<IntType>::value) {
				std::uniform_int_distribution<int64_t> dist(
					(std::numeric_limits<IntType>::min)(),
					(std::numeric_limits<IntType>::max)()
				);
				return static_cast<IntType>(dist(engine));
			}
			else {
				std::uniform_int_distribution<uint64_t> dist(
					0,
					(std::numeric_limits<IntType>::max)()
				);
				return static_cast<IntType>(dist(engine));
			}
		}

		/**
		* \brief Generates a random integral value within a range starting from the minimum representable value
		* of the specified type up to a user-defined maximum bound.
		*
		* \tparam IntType: Integral type used to define the range of possible values.
		* uint32_t by default.
		* 
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type IntType within the inclusive range
		* [std::numeric_limits<IntType>::min(), max].
		*/
		template<typename IntType = uint32_t>
		[[nodiscard("kir::ran::random_int() is useless without use of its return value.")]]
		static IntType random_int(const IntType max) noexcept {
			static_assert(std::is_integral<IntType>::value, "random_int only supports integral types!");
			if constexpr (std::is_signed<IntType>::value) {
				std::uniform_int_distribution<int64_t> dist(
					(std::numeric_limits<IntType>::min)(),
					max
				);
				return static_cast<IntType>(dist(engine));
			}
			else {
				std::uniform_int_distribution<uint64_t> dist(
					0,
					max
				);
				return static_cast<IntType>(dist(engine));
			}
		}

		/**
		* \brief Generates a random integral value within a user-specified inclusive range.
		*
		* \tparam IntType: Integral type used to define the range of possible values.
		*
		* \param min: Lower inclusive bound of the random range.
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type IntType within the inclusive range [min, max].
		*/
		template<typename IntType = uint32_t>
		[[nodiscard("kir::ran::random_int() is useless without use of its return value.")]]
		static IntType random_int(const IntType min, const IntType max) noexcept {
			static_assert(std::is_integral<IntType>::value, "random_int only supports integral types!");
			if constexpr (std::is_signed<IntType>::value) {
				std::uniform_int_distribution<int64_t> dist(
					min,
					max
				);
				return static_cast<IntType>(dist(engine));
			}
			else {
				std::uniform_int_distribution<uint64_t> dist(
					0,
					max
				);
				return static_cast<IntType>(dist(engine));
			}
		}

		/**
		* \brief Generates a random floating point spanning the full range of the specified float type.
		*
		* \tparam FloatType: Float type used to define the range of possible values.
		* float by default.
		* 
		* \return A randomly generated value of type FloatType within the inclusive range
		* [std::numeric_limits<FloatType>::min(), std::numeric_limits<FloatType>::max()].
		*/
		template<typename FloatType = float>
		[[nodiscard("kir::ran::random_float() is useless without use of its return value.")]]
		static FloatType random_float() noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "random_float only supports floating point types!");
			std::uniform_real_distribution<double> dist(
				(std::numeric_limits<FloatType>::min)(), 
				(std::numeric_limits<FloatType>::max)()
			);
			return static_cast<FloatType>(dist(engine));
		}

		/**
		* \brief Generates a random floating point within a range starting from the minimum representable value
		* of the specified type up to a user-defined maximum bound.
		*
		* \tparam FloatType: Float type used to define the range of possible values.
		* float by default.
		*
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type FloatType within the inclusive range
		* [std::numeric_limits<FloatType>::min(), max].
		*/
		template<typename FloatType = float>
		[[nodiscard("kir::ran::random_float() is useless without use of its return value.")]]
		static FloatType random_float(const FloatType max) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "random_float only supports floating point types!");
			std::uniform_real_distribution<double> dist(
				(std::numeric_limits<FloatType>::min)(),
				max
			);
			return static_cast<FloatType>(dist(engine));
		}

		/**
		* \brief Generates a random floating point within a user-specified inclusive range.
		*
		* \tparam FloatType: Float type used to define the range of possible values.
		* float by default.
		*
		* \param min: Lower inclusive bound of the random range.
		* \param max: Upper inclusive bound of the random range.
		*
		* \return A randomly generated value of type FloatType within the inclusive range [min, max].
		*/
		template<typename FloatType = float>
		[[nodiscard("kir::ran::random_float() is useless without use of its return value.")]]
		static FloatType random_float(const FloatType min, const FloatType max) noexcept {
			static_assert(std::is_floating_point<FloatType>::value, "random_float only supports floating point types!");
			std::uniform_real_distribution<double> dist(
				min,
				max
			);
			return static_cast<FloatType>(dist(engine));
		}

		/**
		* \brief Generates a hash of random bytes.
		* 
		* \param len: Length of random hash.
		* 
		* \return A randomly generated hash.
		*/
		[[nodiscard("kir::ran::random_bytes() is useless without use of its return value.")]]
		static kir::bytes random_bytes(const size_t len) noexcept;
	};
}
