#include "impl/kirkode_ran.h"

static_assert(KIR_VERSION_MAJOR == 2 && KIR_VERSION_MINOR == 8, "Library version mismatch between source and kirkode.h");

// Internal
namespace kir {
	namespace ran {
		static thread_local std::mt19937 engine(std::random_device{}());
	}
}

// Operations
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