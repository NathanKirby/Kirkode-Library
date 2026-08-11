#include "impl/kirkode_kson.h"

#include "impl/kirkode_bnd.hpp"
#include "impl/kirkode_str.h"

#include <cctype> // std::isalpha, std::isdigit

static_assert(KIR_VERSION_MAJOR == 2 && KIR_VERSION_MINOR == 7, "Library version mismatch between source and kirkode.h");

namespace kir {
	kson_member::kson_member() noexcept {}
	kson_member::kson_member(const std::string& name, const kson_type expectedType, const size_t contentSize, const std::string& content) noexcept
		: expected_type(expectedType), content_size(contentSize) {
		if (K_NOEXCEPT(this->name.reserve(name.size()))) {
			for (const char c : name) this->name.push_back(c);
		}
		if (K_NOEXCEPT(this->content.reserve(contentSize))) {
			for (const char c : content) this->content.push_back(c);
		}
	}
	kson_member::kson_member(const std::string& name, const kson_type expectedType, const std::string& content) noexcept
		: kson_member(name, expectedType, content.size(), content) {}
	kson_member::kson_member(const std::string& name, const std::string& content) noexcept
		: kson_member(name, kson_type::UNSPECIFIED, content.size(), content) {}
	void kson_member::clear() noexcept {
		std::string().swap(name);
		std::string().swap(content);
		expected_type = kson_type::UNSPECIFIED;
		content_size = 0;
	}
}

namespace kir {
	bool kson_builder_member::allocate_builder() noexcept {
		try {
			name.reserve(64);
			expected_type_digits.reserve(2);
			content_size_digits.reserve(20);
		}
		catch (...) { return false; }
		return true;
	}
	void kson_builder_member::clear() noexcept {
		name.clear();
		expected_type_digits.clear();
		content_size_digits.clear();
		std::string().swap(content);
		expected_type = kson_type::UNSPECIFIED;
		content_size = 0;
	}
}

namespace kir {
	bool kson::is_legal_member_name(const std::string& name) noexcept {
		if (name.empty()) return false;
		if (name.size() > 64) return false;
		for (const char c : name) {
			if (!std::isalpha(c)
				&& !std::isdigit(c)
				&& c != '_'
				&& c != ' ') {
				return false;
			}
		}
		return true;
	}
	bool kson::serialize(const kson& in, std::string& out) noexcept {
		const std::vector<kson_member>& members = in.get_members();
		size_t requiredSize = 0;
		for (const kson_member& member : members) {
			requiredSize += 4
				+ member.name.size()
				+ 3
				+ 20
				+ member.content_size;
		}
		if (!K_NOEXCEPT(out.reserve(requiredSize))) return false;
		out.clear();
		for (const kson_member& member : members) {
			std::string expectedTypeStr, contentSizeStr;
			if (!str::convert_from_enum(member.expected_type, expectedTypeStr)) return false;
			if (!str::convert_from_int(member.content_size, contentSizeStr)) return false;
			out.push_back('|');
			out.insert(out.end(), member.name.begin(), member.name.end());
			out.push_back(',');
			out.insert(out.end(),
				std::make_move_iterator(expectedTypeStr.begin()),
				std::make_move_iterator(expectedTypeStr.end())
			);
			out.push_back(',');
			out.insert(out.end(),
				std::make_move_iterator(contentSizeStr.begin()),
				std::make_move_iterator(contentSizeStr.end())
			);
			out.push_back(',');
			out.insert(out.end(), member.content.begin(), member.content.end());
		}
		return true;
	}
	bool kson::deserialize(const std::string& in, kson& out) noexcept {
		if (out.get_member_count() > 0) out.clear();
		if (in.empty()) return true;
		kson_builder_member builder;
		if (!builder.allocate_builder()) return false;
		uint8_t ccc = 0;
		size_t contentRemaining = 0;
		size_t start = (in[0] == '|') ? 1 : 0;
		for (size_t i = start; i < in.size(); ++i) {
			const char c = in[i];
			if (contentRemaining > 0) {
				builder.content.push_back(c);
				--contentRemaining;
				if (contentRemaining == 0) {
					if (!K_NOEXCEPT(out.members.push_back(static_cast<kson_member>(builder)))) return false;
					builder.clear();
					ccc = 0;
				}
			}
			else {
				if (c == '|') {
					builder.clear();
					ccc = 0;
				}
				else if (c == ',') {
					++ccc;
					if (ccc == 2) {
						uint8_t expectedType = 0;
						for (const char d : builder.expected_type_digits) {
							if (d >= '0' && d <= '9') {
								expectedType = static_cast<uint8_t>(expectedType * 10 + (d - '0'));
							}
						}
						builder.expected_type = static_cast<kson_type>(expectedType);
					}
					else if (ccc == 3) {
						size_t contentSize = 0;
						for (const char d : builder.content_size_digits) {
							if (d >= '0' && d <= '9') {
								contentSize = contentSize * 10 + static_cast<size_t>(d - '0');
							}
						}
						builder.content_size = contentSize;
						contentRemaining = contentSize;
						if (contentSize == 0) {
							if (!K_NOEXCEPT(out.members.push_back(static_cast<kson_member>(builder)))) return false;
							builder.clear();
							ccc = 0;
						}
						else if (!K_NOEXCEPT(builder.content.reserve(contentSize))) {
							return false;
						}
					}
				}
				else {
					if (ccc == 0) builder.name.push_back(c);
					else if (ccc == 1) builder.expected_type_digits.push_back(c);
					else if (ccc == 2) builder.content_size_digits.push_back(c);
					else if (ccc == 3) builder.content.push_back(c);
				}
			}
		}
		return true;
	}
}

namespace kir {
	bool kson::reserve(const size_t newCapacity) noexcept {
		return K_NOEXCEPT(members.reserve(newCapacity));
	}
	bool kson::add_member(const std::string& name, const kson_type expectedType, const std::string& content) noexcept {
		const size_t contentSize = content.size();
		if (contentSize == 0) return false;
		if (!is_legal_member_name(name)) return false;
		return K_NOEXCEPT(members.push_back(kson_member(name, expectedType, contentSize, content)));
	}
	bool kson::add_member(const std::string& name, const std::string& content) noexcept {
		return add_member(name, kson_type::UNSPECIFIED, content);
	}
	void kson::clear() noexcept {
		std::vector<kson_member>().swap(members);
	}
	const kson_member* kson::get_member(const std::string& name) const noexcept {
		for (const kson_member& member : members) {
			if (member.name == name) {
				return &member;
			}
		}
		return nullptr;
	}
	const std::vector<kson_member>& kson::get_members() const noexcept {
		return members;
	}
	size_t kson::get_member_count() const noexcept {
		return members.size();
	}
}