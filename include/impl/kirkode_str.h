#pragma once

#include "kirkode_types.h"

#include <unordered_map>
#include <vector>
#include <mutex>

namespace kirkode {
	/**
	 * \brief String filtering and sanitization utilities using reusable character lists.
	 *
	 * Provides static functions for registering character whitelist and blacklist
	 * definitions, then applying those lists to strings.
	 *
	 * Lists are identified by a user-defined ID and stored internally for reuse.
	 *
	 * This class is thread-safe and does not require instantiation.
	 */
	class str {
	private:
		inline static std::mutex listMutex;
		inline static std::unordered_map<uint8_t, std::vector<char>> whitelistMap;
		inline static std::unordered_map<uint8_t, std::vector<char>> blacklistMap;
	public:
		/**
		* \brief Adds a whitelist to the string cleaning logic with a given ID.
		*
		* \param listId: The ID for the added whitelist.
		* \param whitelist: The list of chars you want to be whitelist.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool add_whitelist(const uint8_t listId, std::vector<char>&& whitelist) noexcept;

		/**
		* \brief Adds a blacklist to the string cleaning logic with a given ID.
		*
		* \param listId: The ID for the added blacklist.
		* \param blacklist: The list of chars you want to be blacklisted.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool add_blacklist(const uint8_t listId, std::vector<char>&& blacklist) noexcept;
	public:
		/**
		* \brief Cleans a string by removing every char that doesn't exists in a whitelist.
		*
		* \param listId: The ID of the whitelist to clean the string with.
		* \param string: The string to clean.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool clean_with_whitelist(const uint8_t listId, std::string& string) noexcept;

		/**
		* \brief Cleans a string by removing every char which exists in a blacklist.
		* 
		* \param listId: The ID of the blacklist to clean the string with.
		* \param string: The string to clean.
		* 
		* \return true if successful, false if otherwise.
		*/
		static bool clean_with_blacklist(const uint8_t listId, std::string& string) noexcept;
	};
}