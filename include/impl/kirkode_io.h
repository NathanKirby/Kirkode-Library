#pragma once

#include "kirkode_types.h"

#include <string>

namespace kir {
	/**
	 * \brief File and directory management utilities.
	 *
	 * Provides static functions for checking file and directory existence,
	 * reading and writing text or binary data, removing files or directories,
	 * and moving or renaming filesystem entries.
	 *
	 * This class is thread-safe and does not require instantiation.
	 */
	class io {
	public:
		/**
		* \brief Checks if a path exists and points to a regular file.
		*
		* \param path: The path to check.
		*
		* \return true if the path is a valid file, false if otherwise.
		*/
		[[nodiscard("kir::io::file_exists() is pointless without use of its return value.")]]
		static bool file_exists(const std::string& path) noexcept;

		/**
		* \brief Checks if a path exists and points to a directory.
		*
		* \param path: The path to check.
		*
		* \return true if the path is a valid directory, false if otherwise.
		*/
		[[nodiscard("kir::io::directory_exists() is pointless without use of its return value.")]]
		static bool directory_exists(const std::string& path) noexcept;

		/**
		* \brief Writes binary data to a file.
		*
		* \param path: The path of the file to write.
		* \param binary: The binary data to write.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool write_binary(const std::string& path, const kir::bytes& binary) noexcept;

		/**
		* \brief Writes text data to a file.
		*
		* \param path: The path of the file to write.
		* \param text: The text data to write.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool write_text(const std::string& path, const std::string& text) noexcept;

		/**
		* \brief Reads binary data from a file.
		*
		* \param path: The path of the file to read.
		* \param outBinary: The buffer to store the read binary data.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool read_binary(const std::string& path, kir::bytes& outBinary) noexcept;

		/**
		* \brief Reads text data from a file.
		*
		* \param path: The path of the file to read.
		* \param outText: The string to store the read text data.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool read_text(const std::string& path, std::string& outText) noexcept;

		/**
		* \brief Removes a file from the filesystem.
		*
		* \param path: The path of the file to remove.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool remove_file(const std::string& path) noexcept;

		/**
		* \brief Removes a directory and all of its contents from the filesystem.
		*
		* \param path: The path of the directory to remove.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool remove_directory(const std::string& path) noexcept;

		/**
		* \brief Renames a file or directory.
		*
		* The new name may be a simple filename, which keeps the original parent
		* directory, or a full path, which moves the entry while renaming it.
		*
		* \param path: The path of the file or directory to rename.
		* \param newName: The new name or destination path.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool rename(const std::string& path, const std::string& newName) noexcept;

		/**
		* \brief Moves a file or directory to a new location.
		*
		* \param path: The path of the file or directory to move.
		* \param newPath: The destination path.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool move(const std::string& path, const std::string& newPath) noexcept;
	};
}