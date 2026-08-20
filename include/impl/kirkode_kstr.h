#pragma once
#ifndef KIR_EXCLUDE_KSTR
#include "kirkode_types.h"

#include <string>
#include <cstdint>

namespace kir {
	/**
	 * \brief Lightweight dynamic string with manual capacity control and validity tracking.
	 *
	 * The kstr class provides a custom string implementation that owns a contiguous
	 * buffer of characters. It supports:
	 *
	 * 1: Explicit capacity reservation and growth.
	 * 2: Appending characters, C-strings, std::string, and other kstr instances.
	 * 3: Conversion to std::string.
	 * 4: Iterator access via begin()/end().
	 * 5: Validity tracking so the type can act as a simple optional return value
	 *    (use return_invalid() on error paths and check valid() on the caller side).
	 *
	 * All public operations are marked noexcept. Allocation failures set the
	 * internal valid flag to false and return false from the mutating methods.
	 * The class never throws.
	 *
	 * This class is not null-terminated; the stored length is authoritative.
	 */
	class kstr {
	private:
		// Tells whether the kstr is corrupted or not.
		bool _valid = true;
		// Dynamically allocated char array.
		char* _data = nullptr;
		// Length of char array.
		kir::size _len = 0;
		// Allocation sized/capacity for char array.
		kir::size _capacity = 0;
	private:
		bool reallocate(const kir::size new_capacity) noexcept;
	public:
		/**
		 * \brief Default constructor. Creates an empty, valid kstr with zero capacity.
		 */
		kstr() noexcept;

		/**
		 * \brief Constructs a kstr with an explicit validity state and no data.
		 *
		 * \param valid: Initial validity flag. Pass false to create an already-invalid instance.
		 */
		kstr(const bool valid) noexcept;

		/**
		 * \brief Constructs a kstr by copying a null-terminated C-string.
		 *
		 * On allocation failure the resulting object is marked invalid.
		 *
		 * \param v: Null-terminated source string. May be nullptr (treated as empty).
		 */
		kstr(const char* v) noexcept;

		/**
		 * \brief Destructor. Releases any owned buffer.
		 */
		~kstr() noexcept;
	public:
		/**
		 * \brief Ensures the internal buffer can hold at least new_capacity characters.
		 *
		 * Does nothing (and returns true) if the current capacity is already sufficient.
		 * On allocation failure the object is marked invalid and false is returned.
		 *
		 * \param new_capacity: Desired minimum capacity.
		 * \return true on success, false on allocation failure.
		 */
		bool reserve(const kir::size new_capacity) noexcept;

		/**
		 * \brief Increases the capacity by the given amount.
		 *
		 * \param additional_capacity: Number of extra characters to reserve.
		 * \return true on success, false if additional_capacity is zero or allocation fails.
		 */
		bool add_capacity(const kir::size additional_capacity) noexcept;

		/**
		 * \brief Appends a single character.
		 *
		 * Grows the buffer by one if necessary. On allocation failure the object
		 * is marked invalid and false is returned.
		 *
		 * \param c: Character to append.
		 * \return true on success, false on allocation failure.
		 */
		bool push_back(const char c) noexcept;

		/**
		 * \brief Appends a null-terminated C-string.
		 *
		 * \param input: Null-terminated source. Empty or null input returns false.
		 * \return true on success, false on empty input or allocation failure.
		 */
		bool push_back(const char* input) noexcept;

		/**
		 * \brief Appends the contents of a std::string.
		 *
		 * \param input: Source string. Empty input returns false.
		 * \return true on success, false on empty input, size overflow, or allocation failure.
		 */
		bool push_back(const std::string& input) noexcept;

		/**
		 * \brief Appends the contents of another kstr.
		 *
		 * \param input: Source kstr. Empty input returns false.
		 * \return true on success, false on empty input or allocation failure.
		 */
		bool push_back(const kstr& input) noexcept;

		/**
		 * \brief Reduces capacity to exactly match the current length.
		 *
		 * \return true on success, false on allocation failure.
		 */
		bool shrink_to_fit() noexcept;

		/**
		 * \brief Sets the length to zero without releasing the buffer.
		 */
		void clear() noexcept;

		/**
		 * \brief Releases the internal buffer and resets length/capacity to zero.
		 *
		 * The object remains valid unless it was already invalid.
		 */
		void deallocate() noexcept;

		/**
		 * \brief Returns a std::string copy of the current contents.
		 *
		 * Returns an empty string if the kstr is invalid or empty.
		 * Allocation failure inside std::string also yields an empty result.
		 *
		 * \return A std::string containing a copy of the data, or empty on error.
		 */
		std::string string() const noexcept;
	public:
		/**
		 * \brief Returns a mutable pointer to the first character.
		 *
		 * \return Pointer to the start of the buffer, or nullptr if empty/unallocated.
		 */
		char* begin() noexcept;

		/**
		 * \brief Returns a mutable pointer one past the last character.
		 *
		 * \return Pointer to the end of the used range.
		 */
		char* end() noexcept;

		/**
		 * \brief Returns a const pointer to the first character.
		 *
		 * \return Const pointer to the start of the buffer, or nullptr if empty/unallocated.
		 */
		const char* begin() const noexcept;

		/**
		 * \brief Returns a const pointer one past the last character.
		 *
		 * \return Const pointer to the end of the used range.
		 */
		const char* end() const noexcept;
	public:
		/**
		 * \brief Returns a const pointer to the underlying buffer.
		 *
		 * The buffer is not null-terminated; use size() to determine length.
		 *
		 * \return Const pointer to the data, or nullptr if unallocated.
		 */
		const char* data() const noexcept;

		/**
		 * \brief Returns a mutable pointer to the underlying buffer.
		 *
		 * The buffer is not null-terminated; use size() to determine length.
		 *
		 * \return Mutable pointer to the data, or nullptr if unallocated.
		 */
		char* data() noexcept;

		/**
		 * \brief Reports whether the string contains no characters.
		 *
		 * \return true if size() == 0.
		 */
		bool empty() const noexcept;

		/**
		 * \brief Reports whether the object is still valid.
		 *
		 * An object becomes invalid after an allocation failure or an explicit
		 * call to mark_invalid(). Use this together with return_invalid() to
		 * implement optional-style error handling.
		 *
		 * \return true if the object is valid.
		 */
		bool valid() const noexcept;

		/**
		 * \brief Returns the current number of characters.
		 *
		 * \return Length of the stored data.
		 */
		kir::size size() const noexcept;

		/**
		 * \brief Returns the current allocated capacity.
		 *
		 * \return Number of characters the buffer can hold without reallocation.
		 */
		kir::size capacity() const noexcept;

		/**
		 * \brief Explicitly marks the object as invalid.
		 *
		 * Subsequent calls to valid() will return false. Does not free memory.
		 */
		void mark_invalid() noexcept;
	public:
		/**
		 * \brief Returns a shared invalid sentinel instance.
		 *
		 * Intended for error-return paths so that callers can write:
		 * \code
		 * if (error) return kir::kstr::return_invalid();
		 * \endcode
		 * and later test the result with .valid().
		 *
		 * \return A kstr that is already marked invalid and contains no data.
		 */
		static kstr return_invalid() noexcept;
	public:
		char operator[](const kir::size index) const noexcept;
		bool operator==(const kstr& other) const noexcept;
		bool operator!=(const kstr& other) const noexcept;
		void operator+=(const kstr& other) noexcept;
	public:
		kstr& operator<<(const char* input) noexcept;
		kstr& operator<<(const char input) noexcept;
		kstr& operator<<(const std::string& input) noexcept;
		kstr& operator<<(const kstr& input) noexcept;
		kstr& operator<<(const bool input) noexcept;
		kstr& operator<<(const uint8_t input) noexcept;
		kstr& operator<<(const uint16_t input) noexcept;
		kstr& operator<<(const uint32_t input) noexcept;
		kstr& operator<<(const uint64_t input) noexcept;
		kstr& operator<<(const int8_t input) noexcept;
		kstr& operator<<(const int16_t input) noexcept;
		kstr& operator<<(const int32_t input) noexcept;
		kstr& operator<<(const int64_t input) noexcept;
		kstr& operator<<(const float input) noexcept;
		kstr& operator<<(const double input) noexcept;
	};
}
#endif // KIR_EXCLUDE_KSTR