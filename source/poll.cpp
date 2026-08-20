#include "impl/kirkode_poll.h"

static_assert(KIR_VERSION_MAJOR == 2 && KIR_VERSION_MINOR == 8, "Library version mismatch between source and kirkode.h");

// Constructors
namespace kir {
	flag_poll::flag_poll() noexcept = default;
	flag_poll::flag_poll(const uint64_t value) noexcept {
		set_value(value);
	}
	flag_poll::flag_poll(const kir::bytes buffer) noexcept {
		for (kir::size i = 0; i < buffer.size(); ++i) {
			_fields[i] = buffer[i];
		}
	}
}

// Interaction
namespace kir {
	void flag_poll::set_flag(const flag_bit flag) noexcept {
		const uint8_t bit = static_cast<uint8_t>(flag);
		const uint8_t field = bit / 8;
		const uint8_t offset = field * 8;
		_fields[field] |= (1 << (bit - offset));
	}
	void flag_poll::clear_flag(const flag_bit flag) noexcept {
		const uint8_t bit = static_cast<uint8_t>(flag);
		const uint8_t field = bit / 8;
		const uint8_t offset = field * 8;
		_fields[field] &= ~(1 << (bit - offset));
	}
	void flag_poll::clear_all() noexcept {
		for (uint8_t i = 0; i < 8; ++i) _fields[i] = 0;
	}
	void flag_poll::set_value(const uint64_t value) noexcept {
		for (size_t i = 0; i < 8; ++i) {
			_fields[i] = static_cast<uint8_t>(value >> (i * 8));
		}
	}
}

// Getters
namespace kir {
	bool flag_poll::flag_set(const flag_bit flag) const noexcept {
		const uint8_t bit = static_cast<uint8_t>(flag);
		const uint8_t field = bit / 8;
		const uint8_t offset = field * 8;
		return _fields[field] & (1 << (bit - offset));
	}
	bool flag_poll::any_flag_set() const noexcept {
		for (uint8_t i = 0; i < 8; ++i) {
			if (_fields[i] != 0) {
				return true;
			}
		}
		return false;
	}
	kir::size flag_poll::get_size() const noexcept {
		kir::size size = 0;
		for (uint8_t i = 0; i < 8; ++i) {
			if (_fields[i] != 0) {
				size = i + 1;
			}
		}
		return size;
	}
	uint64_t flag_poll::get_value() const noexcept {
		uint64_t value = 0;
		for (size_t i = 0; i < 8; ++i) {
			value |= static_cast<uint64_t>(_fields[i]) << (i * 8);
		}
		return value;
	}
	kir::bytes flag_poll::to_bytes() const noexcept {
		const kir::size size = get_size();
		kir::bytes buffer;
		if (size == 0) return buffer;
		try { buffer.reserve(size); }
		catch (...) { return buffer; }
		for (kir::size i = 0; i < size; ++i) {
			buffer.push_back(_fields[i]);
		}
		return buffer;
	}
}