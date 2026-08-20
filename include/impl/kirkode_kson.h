#pragma once
#ifndef KIR_EXCLUDE_KSON
#include "kirkode_types.h"

#include <string>
#include <vector>
#include <cstdint>

namespace kir {
	/**
	 * \brief Specifies the expected type of a KSON member's content.
	 *
	 * KSON stores member content as a string, while this enumeration specifies
	 * the type that the receiving application is expected to interpret the
	 * content as.
	 */
	enum class kson_type : uint8_t {
		UNSPECIFIED = 0,

		UINT8 = 1,
		UINT16 = 2,
		UINT32 = 3,
		UINT64 = 4,

		INT8 = 5,
		INT16 = 6,
		INT32 = 7,
		INT64 = 8,

		BOOL = 9,
		STRING = 10,
		FLOAT = 11,
		DOUBLE = 12
	};

	/**
	 * \brief Represents a single member in a KSON data structure.
	 *
	 * A KSON member consists of a name, an expected content type, the size of
	 * its content, and the content itself.
	 */
	struct kson_member {
	public:
		/**
		 * \brief Name of the KSON member.
		 *
		 * The name identifies the member within a KSON object.
		 *
		 * Valid member names may contain alphabetic characters, numeric
		 * characters, underscores, and spaces, and may be up to 64 characters
		 * long.
		 */
		std::string name;

		/**
		 * \brief Expected type of the member's content.
		 *
		 * Specifies the type that the receiving application is expected to
		 * interpret content as.
		 *
		 * Defaults to kson_type::UNSPECIFIED.
		 */
		kson_type expected_type = kson_type::UNSPECIFIED;

		/**
		 * \brief Size of the member's content in characters.
		 *
		 * This value corresponds to the number of characters stored in content.
		 */
		size_t content_size = 0;

		/**
		 * \brief Content of the KSON member.
		 *
		 * The content is stored as a string regardless of expected_type.
		 * The receiving application is responsible for interpreting the
		 * content according to expected_type.
		 */
		std::string content;
	public:
		/**
		 * \brief Constructs an empty KSON member.
		 *
		 * The member is initialized with an unspecified expected type,
		 * a content size of zero, and empty name and content strings.
		 */
		kson_member() noexcept;

		/**
		 * \brief Constructs a KSON member with the specified content size.
		 *
		 * \param name: Name of the member.
		 * \param expected_type: Expected type of the member's content.
		 * \param content_size: Size of the content.
		 * \param content: Content of the member.
		 */
		kson_member(
			const std::string& name,
			const kson_type expected_type,
			const size_t content_size,
			const std::string& content
		) noexcept;

		/**
		 * \brief Constructs a KSON member and determines the content size automatically.
		 *
		 * \param name: Name of the member.
		 * \param expected_type: Expected type of the member's content.
		 * \param content: Content of the member.
		 *
		 * \details
		 * content_size is initialized to content.size().
		 */
		kson_member(
			const std::string& name,
			const kson_type expected_type,
			const std::string& content
		) noexcept;

		/**
		 * \brief Constructs a KSON member with an unspecified expected type.
		 *
		 * \param name: Name of the member.
		 * \param content: Content of the member.
		 *
		 * \details
		 * expected_type is initialized to kson_type::UNSPECIFIED and
		 * content_size is initialized to content.size().
		 */
		kson_member(
			const std::string& name,
			const std::string& content
		) noexcept;
	public:
		/**
		 * \brief Clears the KSON member.
		 *
		 * Removes the member name and content, resets content_size to zero,
		 * and resets expected_type to kson_type::UNSPECIFIED.
		 */
		virtual void clear() noexcept;
	};

	/**
	 * \brief Internal member type used while constructing a KSON object from serialized data.
	 *
	 * This type is primarily intended for use by the KSON implementation
	 * and is not normally required when constructing KSON data manually.
	 */
	struct kson_builder_member : kson_member {
	public:
		/**
		 * \brief Temporary storage for the serialized expected-type value.
		 *
		 * During deserialization, the numeric characters representing
		 * expected_type are stored here before being converted to kson_type.
		 */
		std::string expected_type_digits;

		/**
		 * \brief Temporary storage for the serialized content-size value.
		 *
		 * During deserialization, the numeric characters representing
		 * content_size are stored here before being converted to size_t.
		 */
		std::string content_size_digits;

	public:
		/**
		* \brief Preallocates memory used while building a KSON member.
		*
		* Reserves memory for the member name, expected-type digits,
		* and content-size digits to reduce allocations during deserialization.
		*
		* \return true if all required allocations succeeded, false otherwise.
		*/
		bool allocate_builder() noexcept;

		/**
		 * \brief Clears the builder member.
		 *
		 * Clears the member's name, temporary parsing data, and content,
		 * and resets expected_type and content_size to their default values.
		 */
		void clear() noexcept override;
	};

	/**
	 * \brief Represents a collection of KSON members.
	 *
	 * kson provides functionality for constructing, accessing, serializing,
	 * and deserializing KSON data.
	 *
	 * Member content is stored as a string and can represent different types
	 * according to the associated kson_type value.
	 */
	class kson {
	private:
		// Array of kson members.
		std::vector<kson_member> _members;
	public:
		/**
		 * \brief Reserves capacity for KSON members.
		 *
		 * \param new_capacity: Number of members to reserve space for.
		 *
		 * \return true if the requested capacity was successfully reserved,
		 * false if memory allocation failed.
		 */
		bool reserve(const size_t new_capacity) noexcept;

		/**
		 * \brief Adds a member to the KSON object.
		 *
		 * \param name: Name of the member.
		 * \param expected_type: Expected type of the member's content.
		 * \param content: Content of the member.
		 *
		 * \return true if the member was successfully added, false otherwise.
		 */
		bool add_member(
			const std::string& name,
			const kson_type expected_type,
			const std::string& content
		) noexcept;

		/**
		 * \brief Adds a member with an unspecified expected type.
		 *
		 * \param name: Name of the member.
		 * \param content: Content of the member.
		 *
		 * \return true if the member was successfully added, false otherwise.
		 */
		bool add_member(
			const std::string& name,
			const std::string& content
		) noexcept;

		/**
		 * \brief Removes all members from the KSON object.
		 *
		 * The KSON object is returned to an empty state.
		 */
		void clear() noexcept;
	public:
		/**
		* \brief Retrieves a member by name.
		*
		* \param name: Name of the member to search for.
		*
		* \return Pointer to the first member with the specified name,
		* or nullptr if no matching member exists.
		*/
		[[nodiscard("kir::kson::get_member() is pointless without use of its return value.")]]
		const kson_member* get_member(const std::string& name) const noexcept;

		/**
		 * \brief Retrieves all KSON members.
		 *
		 * \return Constant reference to the internal collection of members.
		 */
		[[nodiscard("kir::kson::get_members() is pointless without use of its return value.")]]
		const std::vector<kson_member>& get_members() const noexcept;

		/**
		 * \brief Retrieves the number of members in the KSON object.
		 *
		 * \return Number of members currently stored.
		 */
		[[nodiscard("kir::kson::get_member_count() is pointless without use of its return value.")]]
		size_t get_member_count() const noexcept;
	public:
		/**
		* \brief Determines whether a member name is valid.
		*
		* \param name: Member name to validate.
		*
		* \return true if the name is valid, false otherwise.
		*/
		[[nodiscard("kir::kson::is_legal_member_name() is pointless without use of its return value.")]]
		static bool is_legal_member_name(const std::string& name) noexcept;
	public:
		/**
		* \brief Serializes a KSON object into its string representation.
		*
		* \param in: KSON object to serialize.
		* \param out: String that receives the serialized KSON data.
		*
		* \return true if serialization succeeded, false if memory allocation
		* or string construction failed.
		*/
		static bool serialize(const kson& in, std::string& out) noexcept;

		/**
		 * \brief Deserializes a serialized KSON string.
		 *
		 * \param in: Serialized KSON data.
		 * \param out: KSON object that receives the deserialized members.
		 *
		 * \return true if deserialization completed successfully, false if
		 * memory allocation failed.
		 */
		static bool deserialize(const std::string& in, kson& out) noexcept;
	};
}
#endif // KIR_EXCLUDE_KSON