#pragma once
#ifndef KIR_EXCLUDE_IO
#include "kirkode_types.h"

#include <string>
#include <filesystem>
#include <fstream>

namespace kir {
	/**
	 * \brief File and directory management utilities.
	 *
	 * Provides static functions for checking file and directory existence,
	 * reading and writing text or binary data, removing files or directories,
	 * and moving or renaming filesystem entries.
	 *
	 * This class is thread-safe and does not require instantiation.
	 * 
	 * Note: Requires C++17 or later due to use of std::filesystem.
	 */
	namespace io {
		/**
		* \brief Checks if a path exists and points to a regular file.
		*
		* \param path: The path to check.
		*
		* \return true if the path is a valid file, false if otherwise.
		*/
		[[nodiscard("kir::io::file_exists() is pointless without use of its return value.")]]
		static bool file_exists(const std::string& path) noexcept {
			bool exists = false;
			try {
				const std::filesystem::path p = path;
				exists = std::filesystem::exists(p) && std::filesystem::is_regular_file(p);
			}
			catch (...) { return false; }
			return exists;
		}

		/**
		* \brief Checks if a path exists and points to a directory.
		*
		* \param path: The path to check.
		*
		* \return true if the path is a valid directory, false if otherwise.
		*/
		[[nodiscard("kir::io::directory_exists() is pointless without use of its return value.")]]
		static bool directory_exists(const std::string& path) noexcept {
			bool exists = false;
			try {
				const std::filesystem::path p = path;
				exists = std::filesystem::exists(p) && std::filesystem::is_directory(p);
			}
			catch (...) { return false; }
			return exists;
		}

		/**
		* \brief Writes binary data to a file.
		*
		* \param path: The path of the file to write.
		* \param binary: The binary data to write.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool write_binary(const std::string& path, const kir::bytes& binary) noexcept {
			try {
				std::ofstream file(path, std::ios::binary);
				if (!file) return false;
				file.write(reinterpret_cast<const char*>(binary.data()), binary.size());
				return file.good();
			}
			catch (...) { return false; }
		}

		/**
		* \brief Writes text data to a file.
		*
		* \param path: The path of the file to write.
		* \param text: The text data to write.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool write_text(const std::string& path, const std::string& text) noexcept {
			try {
				std::ofstream file(path, std::ios::binary);
				if (!file) return false;
				file.write(text.data(), text.length());
				return file.good();
			}
			catch (...) { return false; }
		}

		/**
		* \brief Reads binary data from a file.
		*
		* \param path: The path of the file to read.
		* \param outBinary: The buffer to store the read binary data.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool read_binary(const std::string& path, kir::bytes& outBinary) noexcept {
			try {
				std::ifstream file(path, std::ios::binary);
				if (!file) return false;
				file.seekg(0, std::ios::end);
				const int64_t size = static_cast<int64_t>(file.tellg());
				if (size < 0) return false;
				file.seekg(0, std::ios::beg);
				outBinary.resize(static_cast<size_t>(size));
				if (size > 0) {
					file.read(reinterpret_cast<char*>(outBinary.data()), size);
				}
				return file.good() || file.eof();
			}
			catch (...) { return false; }
		}

		/**
		* \brief Reads text data from a file.
		*
		* \param path: The path of the file to read.
		* \param outText: The string to store the read text data.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool read_text(const std::string& path, std::string& outText) noexcept {
			try {
				std::ifstream file(path);
				if (!file) return false;
				file.seekg(0, std::ios::end);
				const int64_t size = static_cast<int64_t>(file.tellg());
				if (size < 0) return false;
				file.seekg(0, std::ios::beg);
				outText.resize(static_cast<size_t>(size));
				if (!file.read(&outText[0], size) && size > 0) return false;
				return true;
			}
			catch (...) { return false; }
		}

		/**
		* \brief Creates an empty file.
		*
		* \param path: The path of the new file.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool touch_file(const std::string& path) noexcept {
			try {
				std::ofstream file(path);
				return file.is_open();
			}
			catch (...) { return false; }
		}

		/**
		* \brief Creates a new folder/directory.
		*
		* \param path: The path of the new directory.
		*
		* \return true if a new directory was made, false if error or path is occupied.
		*/
		static bool touch_directory(const std::string& path) noexcept {
			std::error_code ec;
			std::filesystem::create_directory(path, ec);
			return !ec;
		}

		/**
		* \brief Removes a file from the filesystem.
		*
		* \param path: The path of the file to remove.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool remove_file(const std::string& path) noexcept {
			try {
				const std::filesystem::path p = path;
				if (!std::filesystem::exists(p)) return false;
				if (!std::filesystem::is_regular_file(p)) return false;
				return std::filesystem::remove(p);
			}
			catch (...) { return false; }
		}

		/**
		* \brief Removes a directory and all of its contents from the filesystem.
		*
		* \param path: The path of the directory to remove.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool remove_directory(const std::string& path) noexcept {
			try {
				const std::filesystem::path p = path;
				if (!std::filesystem::exists(p)) return false;
				if (!std::filesystem::is_directory(p)) return false;
				return std::filesystem::remove_all(p) > 0;
			}
			catch (...) { return false; }
		}

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
		static bool rename(const std::string& path, const std::string& newName) noexcept {
			try {
				const std::filesystem::path p = path;
				std::error_code ec;
				if (!std::filesystem::exists(p, ec)) return false;
				std::filesystem::path newPath = newName;
				if (newPath.has_filename() && newPath.parent_path().empty()) {
					newPath = p.parent_path() / newPath;
				}
				std::filesystem::rename(p, newPath, ec);
				return !ec;
			}
			catch (...) { return false; }
		}

		/**
		* \brief Moves a file or directory to a new location.
		*
		* \param path: The path of the file or directory to move.
		* \param newPath: The destination path.
		*
		* \return true if successful, false if otherwise.
		*/
		static bool move(const std::string& path, const std::string& newPath) noexcept {
			try {
				const std::filesystem::path from = path;
				const std::filesystem::path to = newPath;
				if (!std::filesystem::exists(from)) return false;
				std::filesystem::rename(from, to);
				return true;
			}
			catch (...) { return false; }
		}
	}
}
#endif // KIR_EXCLUDE_IO