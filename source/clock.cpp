#include "impl/kirkode_clock.h"

#include <chrono>

static_assert(KIR_VERSION_MAJOR == 2 && KIR_VERSION_MINOR == 8, "Library version mismatch between source and kirkode.h");

// Internal
namespace kir {
	namespace clock {
		static thread_local kir::time epoch = 0;
	}
}

// kir::clock
namespace kir {
	namespace clock {
		kir::time get_epoch() noexcept {
			return static_cast<kir::time>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()
				).count()
				);
		}
		kir::time time_since(const kir::time time, const kir::time* now) noexcept {
			const kir::time n = now ? *now : get_epoch();
			if (time > n) return 0;
			if (time == n) return 1;
			return n - time;
		}
		bool stopwatch_start() noexcept {
			if (epoch != 0) return false;
			epoch = get_epoch();
			return true;
		}
		bool stopwatch_stop(kir::time& outTime) noexcept {
			if (epoch == 0) return false;
			const kir::time now = get_epoch();
			if (now < epoch) return false;
			outTime = now - epoch;
			epoch = 0;
			return true;
		}
		bool stopwatch_running() noexcept {
			return epoch != 0;
		}
	}
}

// kir::stopwatch
namespace kir {
	stopwatch::stopwatch() noexcept : _running(true), _start(clock::get_epoch()) {}
	kir::time stopwatch::stop() noexcept {
		_lock.lock();
		if (!_running) {
			_lock.unlock();
			return 0;
		}
		const kir::time elapsed = clock::get_epoch() - _start;
		_start = 0;
		_running = false;
		_lock.unlock();
		return elapsed;
	}
	kir::time stopwatch::check() const noexcept {
		_lock.lock();
		if (!_running) {
			_lock.unlock();
			return 0;
		}
		const kir::time elapsed = clock::get_epoch() - _start;
		_lock.unlock();
		return elapsed;
	}
	kir::time stopwatch::restart() noexcept {
		const kir::time now = clock::get_epoch();
		_lock.lock();
		if (_running) {
			const kir::time elapsed = now - _start;
			_start = now;
			_lock.unlock();
			return elapsed;
		}
		_start = now;
		_running = true;
		_lock.unlock();
		return 0;
	}
	bool stopwatch::running() const noexcept {
		_lock.lock();
		const bool runningCopy = _running;
		_lock.unlock();
		return runningCopy;
	}
}