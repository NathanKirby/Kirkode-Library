#include "impl/kirkode_kstr.h"

#include <string>
#include <cstdint>
#include <type_traits>

static_assert(KIR_VERSION_MAJOR == 2 && KIR_VERSION_MINOR == 8, "Library version mismatch between source and kirkode.h");

// Internal
namespace kir {
	static std::allocator<char> _allocator;
	static kstr _invalid = kstr(false);
	static std::string internal_uint_to_string(const uint64_t input) noexcept {
		std::string converted;
		try { converted = std::to_string(input); }
		catch (...) { return converted; }
		return converted;
	}
	static std::string internal_int_to_string(const int64_t input) noexcept {
		std::string converted;
		try { converted = std::to_string(input); }
		catch (...) { return converted; }
		return converted;
	}
	static std::string internal_float_to_string(const double input) noexcept {
		std::string converted;
		try { converted = std::to_string(input); }
		catch (...) { return converted; }
		return converted;
	}
}

// Constructors
namespace kir {
	kstr::kstr() noexcept = default;
	kstr::kstr(const bool valid) noexcept : _valid(valid) {
	}
	kstr::kstr(const char* v) noexcept {
		kir::size len = 0;
		while (true) {
			if (len == (std::numeric_limits<kir::size>::max)()) {
				_valid = false;
				break;
			}
			if (v[len] == '\0') break;
			++len;
		}
		if (_valid && len > 0) {
			if (reallocate(len)) {
				std::memcpy(_data, v, len);
				_len = len;
			}
			else {
				_valid = false;
			}
		}
	}
	kstr::~kstr() noexcept {
		if (_data) _allocator.deallocate(_data, _capacity);
	}
}

// Array Operations
namespace kir {
	bool kstr::reallocate(const kir::size newCapacity) noexcept {
		char* newData = nullptr;
		try { newData = _allocator.allocate(newCapacity); }
		catch (...) { return false; }
		if (_data) {
			std::memcpy(newData, _data, _len > newCapacity ? newCapacity : _len);
			_allocator.deallocate(_data, _capacity);
		}
		if (_len > newCapacity) _len = newCapacity;
		_data = newData;
		_capacity = newCapacity;
		return true;
	}
	bool kstr::reserve(const kir::size newCapacity) noexcept {
		if (newCapacity <= _capacity) return true;
		return reallocate(newCapacity);
	}
	bool kstr::add_capacity(const kir::size additionalCapacity) noexcept {
		if (additionalCapacity == 0) return false;
		return reallocate(_capacity + additionalCapacity);
	}
	bool kstr::push_back(const char c) noexcept {
		if (_len == _capacity) {
			if (!reallocate(_len + 1)) {
				_valid = false;
				return false;
			}
		}
		_data[_len] = c;
		++_len;
		return true;
	}
	bool kstr::push_back(const char* input) noexcept {
		size_t inputSize = 0;
		while (input[inputSize] != '\0' && inputSize + _len < (std::numeric_limits<kir::size>::max)()) {
			++inputSize;
		}
		if (inputSize == 0) return false;
		const kir::size newSize = static_cast<kir::size>(inputSize) + _len;
		if (newSize > _capacity) {
			if (!reallocate(newSize)) {
				_valid = false;
				return false;
			}
		}
		std::memcpy(_data + _len, input, inputSize);
		_len = newSize;
		return true;
	}
	bool kstr::push_back(const std::string& input) noexcept {
		const size_t inputLen = input.size();
		if (inputLen == 0) return false;
		if (inputLen + _len > (std::numeric_limits<kir::size>::max)()) return false;
		const kir::size newLen = static_cast<kir::size>(inputLen) + _len;
		if (newLen > _capacity) {
			if (!reallocate(newLen)) {
				_valid = false;
				return false;
			}
		}
		std::memcpy(_data + _len, input.data(), static_cast<size_t>(newLen - _len));
		_len = newLen;
		return true;
	}
	bool kstr::push_back(const kstr& input) noexcept {
		if (!input.empty()) return false;
		const kir::size newLen = _len + input.size();
		if (newLen > _capacity) {
			if (!reallocate(newLen)) {
				_valid = false;
				return false;
			}
		}
		std::memcpy(_data + _len, input.data(), static_cast<size_t>(newLen - _len));
		_len = newLen;
		return true;
	}
	bool kstr::shrink_to_fit() noexcept {
		return reallocate(_len);
	}
	void kstr::clear() noexcept {
		_len = 0;
	}
	void kstr::deallocate() noexcept {
		if (_capacity == 0 || !_data) return;
		_allocator.deallocate(_data, _capacity);
		_data = nullptr;
		_capacity = 0;
		_len = 0;
	}
	std::string kstr::string() const noexcept {
		std::string result;
		if (!_valid || _len == 0) return result;
		try { result.resize(static_cast<size_t>(_len), '\0'); }
		catch (...) { return std::string{}; }
		for (kir::size i = 0; i < _len; ++i) {
			result[i] = _data[i];
		}
		return result;
	}
}

// Operators
namespace kir {
	char kstr::operator[](const kir::size index) const noexcept {
		if (index > _len) return '\0';
		return _data[index];
	}
	bool kstr::operator==(const kstr& other) const noexcept {
		if (_len != other.size()) return false;
		if (_capacity != other.capacity()) return false;
		for (kir::size i = 0; i < _len; ++i) {
			if (_data[i] != other[i]) return false;
		}
		return true;
	}
	bool kstr::operator!=(const kstr& other) const noexcept {
		if (_len != other.size()) return true;
		if (_capacity != other.capacity()) return true;
		for (kir::size i = 0; i < _len; ++i) {
			if (_data[i] != other[i]) return true;
		}
		return false;
	}
	void kstr::operator+=(const kstr& other) noexcept {
		push_back(other);
	}
	kstr& kstr::operator<<(const char* input) noexcept {
		size_t size = 0;
		while (input[size] != '\0' && size < (std::numeric_limits<kir::size>::max)()) {
			++size;
		}
		if (add_capacity(static_cast<kir::size>(size))) {
			for (size_t i = 0; i < size; ++i) {
				push_back(input[i]);
			}
		}
		return *this;
	}
	kstr& kstr::operator<<(const char input) noexcept {
		push_back(input);
		return *this;
	}
	kstr& kstr::operator<<(const std::string& input) noexcept {
		push_back(input);
		return *this;
	}
	kstr& kstr::operator<<(const kstr& input) noexcept {
		push_back(input);
		return *this;
	}
	kstr& kstr::operator<<(const bool input) noexcept {
		push_back(input ? "true" : "false");
		return *this;
	}
	kstr& kstr::operator<<(const uint8_t input) noexcept {
		push_back(internal_uint_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const uint16_t input) noexcept {
		push_back(internal_uint_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const uint32_t input) noexcept {
		push_back(internal_uint_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const uint64_t input) noexcept {
		push_back(internal_uint_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const int8_t input) noexcept {
		push_back(internal_int_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const int16_t input) noexcept {
		push_back(internal_int_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const int32_t input) noexcept {
		push_back(internal_int_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const int64_t input) noexcept {
		push_back(internal_int_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const float input) noexcept {
		push_back(internal_float_to_string(input));
		return *this;
	}
	kstr& kstr::operator<<(const double input) noexcept {
		push_back(internal_float_to_string(input));
		return *this;
	}
}

// Iterating
namespace kir {
	char* kstr::begin() noexcept {
		return _data;
	}
	char* kstr::end() noexcept {
		return _data + _len;
	}
	const char* kstr::begin() const noexcept {
		return _data;
	}
	const char* kstr::end() const noexcept {
		return _data + _len;
	}
}

// Getters
namespace kir {
	const char* kstr::data() const noexcept {
		return _data;
	}
	bool kstr::empty() const noexcept {
		return _len == 0;
	}
	bool kstr::valid() const noexcept {
		return _valid;
	}
	kir::size kstr::size() const noexcept {
		return _len;
	}
	kir::size kstr::capacity() const noexcept {
		return _capacity;
	}
	void kstr::mark_invalid() noexcept {
		_valid = false;
	}
	kstr kstr::return_invalid() noexcept {
		return _invalid;
	}
}