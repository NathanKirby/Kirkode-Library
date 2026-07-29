#include "impl/kirkode_ran.h"

namespace kir {
	 kir::bytes ran::random_bytes(const size_t len) noexcept {
		kir::bytes buf(len);
		for (size_t i = 0; i < len; ++i) {
			buf[i] = kir::ran::random_int<kir::byte>();
		}
		return buf;
	}
}