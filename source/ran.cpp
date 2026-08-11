#include "impl/kirkode_ran.h"

static_assert(KIR_VERSION_MAJOR == 2 && KIR_VERSION_MINOR == 7, "Library version mismatch between source and kirkode.h");

namespace kir {
	namespace ran {
		static std::mt19937 engine(std::random_device{}());
	}
}

namespace kir {
	namespace ran {
		std::mt19937& get_engine() noexcept {
			return engine;
		}
		kir::bytes random_bytes(const size_t len) noexcept {
			kir::bytes buf(len);
			for (size_t i = 0; i < len; ++i) {
				buf[i] = kir::ran::random_int<kir::byte>();
			}
			return buf;
		}
	}
}