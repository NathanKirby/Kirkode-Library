#pragma once

#include "kirkode_types.h"

namespace kir {
	class clock {
	private:
		// Epoch used for stopwatch functions.
		inline static thread_local kir::time epoch = 0;
	public:
		/**
		* Gets current Epoch in milliseconds.
		*
		* \return Epoch in milliseconds.
		*/
		static kir::time get_epoch() noexcept;

		/**
		* Starts a stopwatch using Epoch as milliseconds.
		*
		* \return True if started, false if already running.
		*/
		static bool stopwatch_start() noexcept;

		/**
		* Stops the stopwatch.
		*
		* \param outTime: Duration in milliseconds.
		* \return True if stopped, false if stopwatch hasn't been started.
		*/
		static bool stopwatch_stop(kir::time& outTime) noexcept;

		/**
		* Checks to see if the stopwatch has been started.
		*
		* \return True if stopwatch has been started and is running, false if otherwise.
		*/
		static bool stopwatch_running() noexcept;
	};
}