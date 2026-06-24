#pragma once

/*
* ==== KIRKODE LIBRARY ====
* Version: 2.5
* Updated: June 23st, 2026
*/

//#define KIR_EXCLUDE_LOG // -------> Excludes kir::log.
//#define KIR_EXCLUDE_CLOCK // -----> Excludes kir::clock and kir::stopwatch.
//#define KIR_EXCLUDE_BIN // -------> Excludes kir::bin.
//#define KIR_EXCLUDE_RAN // -------> Excludes kir::ran.
//#define KIR_EXCLUDE_STR // -------> Excludes kir::str.

//#define KIR_LOG_THREADED // ------> Enables logging to be safe across multiple threads.

#ifndef KIR_EXCLUDE_LOG
#include "impl/kirkode_log.hpp"
#define KLOG(message) kir::log::msg(message)
#endif // KIR_EXCLUDE_LOG

#ifndef KIR_EXCLUDE_CLOCK
#include "impl/kirkode_clock.h"
#endif // KIR_EXCLUDE_CLOCK

#ifndef KIR_EXCLUDE_BIN
#include "impl/kirkode_bin.hpp"
#endif // KIR_EXCLUDE_BIN

#ifndef KIR_EXCLUDE_RAN
#include "impl/kirkode_ran.h"
#endif // KIR_EXCLUDE_RAN

#ifndef KIR_EXCLUDE_STR
#include "impl/kirkode_str.h"
#endif // KIR_EXCLUDE_STR