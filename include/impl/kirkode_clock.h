#pragma once

#include "kirkode_types.h"

namespace kir {
	/**
	 * \brief Provides basic time utilities and a simple global stopwatch facility.
	 *
	 * The clock class offers:
	 * 1: Access to the current system time in milliseconds.
	 * 2: Utility functions for computing time differences.
	 * 3: A lightweight global stopwatch based on a single shared epoch.
	 *
	 * The stopwatch functionality is thread-local and not instance-based:
	 * only one stopwatch per-thread can run at a time using this class.
	 * 
	 * Use kir::stopwatch() for an instance-based stopwatch.
	 */
	class clock {
	private:
		// Epoch used for stopwatch functions.
		inline static thread_local kir::time epoch = 0;
	public:
		/**
		 * \brief Returns the current system time in milliseconds since epoch.
		 *
		 * This uses the system clock and converts it into a millisecond timestamp.
		 *
		 * \return Current time in milliseconds since epoch.
		 */
		[[nodiscard("kir::clock::get_epoch() is useless without use of its return value.")]]
		static kir::time get_epoch() noexcept;

		/**
		* \brief Gets the time since a given epoch.
		* 
		* \param time: Epoch to check against current time.
		* \param now: Optional override for current Epoch.
		* 
		* \return Time since given Epoch. 0 == Given time > Epoch, 1 == Given time == Epoch.
		*/
		[[nodiscard("kir::clock::time_since() is useless without use of its return value.")]]
		static kir::time time_since(const kir::time time, const kir::time* now = nullptr) noexcept;

		/**
		* Starts a stopwatch using Epoch as milliseconds.
		*
		* \return True if started, false if already running.
		*/
		static bool stopwatch_start() noexcept;

		/**
		* \brief Stops the stopwatch.
		*
		* \param outTime: Duration in milliseconds.
		* \return True if stopped, false if stopwatch hasn't been started.
		*/
		static bool stopwatch_stop(kir::time& outTime) noexcept;

		/**
		* \brief Checks to see if the stopwatch has been started.
		*
		* \return True if stopwatch has been started and is running, false if otherwise.
		*/
		[[nodiscard("kir::clock::stopwatch_running() is a getter.")]]
		static bool stopwatch_running() noexcept;
	};
}

#include <mutex>

namespace kir {
	/**
	 * \brief A simple thread-safe stopwatch for measuring elapsed time.
	 * The stopwatch measures elapsed time in milliseconds from the moment it
	 * is constructed or last restarted.
	 * 
	 * This class is thread-safe: all operations may be called from multiple
	 * threads concurrently.
	 */
	class stopwatch {
	private:
		mutable std::mutex lock;
	private:
		bool _running;
		kir::time _start;
	public:
		/**
		 * \brief Constructs a stopwatch and starts it immediately.
		 * The stopwatch begins timing from the moment of construction.
		 * The initial state is running.
		 */
		[[nodiscard("stopwatch::stopwatch() is a constructor and is pointless without use of its return value.")]]
		stopwatch() noexcept;
	public:
		/**
		 * \brief Stops the stopwatch and returns the elapsed time.
		 * If the stopwatch is already stopped, this function returns 0.
		 * Otherwise, it computes the time elapsed since the last start.
		 *
		 * \return Elapsed time in milliseconds since start, or 0 if not running.
		 */
		kir::time stop() noexcept;

		/**
		 * \brief Gets the current elapsed time without stopping the stopwatch.
		 * If the stopwatch is not running, returns 0.
		 * Otherwise, returns the time elapsed since the last start point.
		 *
		 * \return Current elapsed time in milliseconds, or 0 if not running.
		 */
		[[nodiscard("kir::stopwatch::check() is pointless without use of its return value.")]]
		kir::time check() const noexcept;

		/**
		 * \brief Restarts the stopwatch and returns the previous elapsed time.
		 * If the stopwatch is running, it continues timing from the current moment
		 * and returns the elapsed time since the last start.
		 * If the stopwatch is not running, it starts it and returns 0.
		 *
		 * \return Elapsed time in milliseconds if it was running, otherwise 0.
		 */
		kir::time restart() noexcept;
	public:
		/**
		* \brief Checks to see if the stopwatch is running.
		*
		* \return True if the stopwatch is running, False otherwise.
		*/
		[[nodiscard("kir::stopwatch::running() is a getter.")]]
		bool running() const noexcept;
	};
}