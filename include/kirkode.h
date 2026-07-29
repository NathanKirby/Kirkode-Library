#pragma once

// =========================================================================================
// KIRKODE LIBRARY
// =========================================================================================
// Version: 2.6.1
// Updated: July 29th, 2026

// #include <kirkode_types.h> -> Lightweight header to include in header files.
// #include <kirkode.h> -------> Full include header for source files.

// =========================================================================================
// Uncomment defines below to exclude unwanted features. 
// =========================================================================================

//#define KIR_EXCLUDE_LOG // -------> Excludes kir::log.
//#define KIR_EXCLUDE_CLOCK // -----> Excludes kir::clock and kir::stopwatch.
//#define KIR_EXCLUDE_BIN // -------> Excludes kir::bin.
//#define KIR_EXCLUDE_RAN // -------> Excludes kir::ran.
//#define KIR_EXCLUDE_STR // -------> Excludes kir::str.
//#define KIR_EXCLUDE_IO // --------> Excludes kir::io.

//#define KIR_LOG_THREADED // ------> Enables logging to be safe across multiple threads.

// =========================================================================================

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

#ifndef KIR_EXCLUDE_IO
#include "impl/kirkode_io.h"
#endif // KIR_EXCLUDE_IO

// =========================================================================================
// Library Syntax
// =========================================================================================

/**
*  1. Use Snake Case (my_variable_name) for classes, structs, enums, functions, and variables.
*  2. Use capitalized Snake Case (MY_VARIABLE_NAME) for enum values.
*  3. Use enum class instead of enum.
*  4. Functions with no purpose beyond their return values (ex: getters) must be labeled [[nodiscard]].
*  5. Use Camel Case (myVariableName) for function parameters.
*  6. All functions must be noexcept unless specifically labeled otherwise in the name.
*  7. Function parameters that are used only to output information from a function and do not provide input must have their name start with "out" (outResult).
*  8. Bool getters with a name not obviously the name of a getter must have their name start with "is_" (is_valid).
*  9. Use ::type instead of _t for template functions and type traits (ex: std::remove_reference::type instead of std::remove_reference_t).
* 10. Always initialize out variables. 
* 11. Initialize template variables with type constructor (ex: IntType i = IntType{} instead of IntType i = 0).
*/