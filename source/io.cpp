#include "impl/kirkode_io.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace kir {
	bool io::file_exists(const std::string& path) noexcept {
		bool exists = false;
		try {
			const std::filesystem::path p = path;
			exists = std::filesystem::exists(p) && std::filesystem::is_regular_file(p);
		}
		catch (...) {
			return false;
		}
		return exists;
	}
	bool io::directory_exists(const std::string& path) noexcept {
		bool exists = false;
		try {
			const std::filesystem::path p = path;
			exists = std::filesystem::exists(p) && std::filesystem::is_directory(p);
		}
		catch (...) {
			return false;
		}
		return exists;
	}
	bool io::write_binary(const std::string& path, const kir::bytes& binary) noexcept {
		try {
			std::ofstream file(path, std::ios::binary);
			if (!file) return false;
			file.write(reinterpret_cast<const char*>(binary.data()), binary.size());
			return file.good();
		}
		catch (...) {
			return false;
		}
	}
	bool io::write_text(const std::string& path, const std::string& text) noexcept {
		try {
			std::ofstream file(path, std::ios::binary);
			if (!file) return false;
			file.write(text.data(), text.length());
			return file.good();
		}
		catch (...) {
			return false;
		}
	}
	bool io::read_binary(const std::string& path, kir::bytes& outBinary) noexcept {
		try {
			std::ifstream file(path, std::ios::binary);
			if (!file) return false;
			file.seekg(0, std::ios::end);
			const size_t size = static_cast<size_t>(file.tellg());
			file.seekg(0, std::ios::beg);
			outBinary.resize(size);
			if (size > 0) {
				file.read(reinterpret_cast<char*>(outBinary.data()), size);
			}
			return file.good() || file.eof();
		}
		catch (...) {
			return false;
		}
	}
	bool io::read_text(const std::string& path, std::string& outText) noexcept {
		try {
			std::ifstream file(path);
			if (!file) return false;;
			std::stringstream buffer;
			buffer << file.rdbuf();
			outText = buffer.str();
			return true;
		}
		catch (...) {
			return false;
		}
	}
	bool io::remove_file(const std::string& path) noexcept {
		try {
			const std::filesystem::path p = path;
			if (!std::filesystem::exists(p)) return false;
			if (!std::filesystem::is_regular_file(p)) return false;
			return std::filesystem::remove(p);
		}
		catch (...) {
			return false;
		}
	}
	bool io::remove_directory(const std::string& path) noexcept {
		try {
			const std::filesystem::path p = path;
			if (!std::filesystem::exists(p)) return false;
			if (!std::filesystem::is_directory(p)) return false;
			return std::filesystem::remove_all(p) > 0;
		}
		catch (...) {
			return false;
		}
	}
	bool io::rename(const std::string& path, const std::string& newName) noexcept {
		try {
			const std::filesystem::path p = path;
			std::error_code ec;
			if (!std::filesystem::exists(p, ec)) return false;
			std::filesystem::path newPath = newName;
			if (newPath.has_filename() && newPath.parent_path().empty()) {
				newPath = p.parent_path() / newPath;
			}
			std::filesystem::rename(p, newPath, ec);
			
			return true;
		}
		catch (...) {
			return false;
		}
	}
	bool io::move(const std::string& path, const std::string& newPath) noexcept {
		try {
			const std::filesystem::path from = path;
			const std::filesystem::path to = newPath;
			if (!std::filesystem::exists(from)) return false;
			std::filesystem::rename(from, to);
			return true;
		}
		catch (...) {
			return false;
		}
	}
}