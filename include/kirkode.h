#pragma once

// =========================================================================================
// KIRKODE LIBRARY
// =========================================================================================

// Version: 2.7
// Updated: August 10th, 2026

// #include <kirkode_types.h> -> Lightweight header to include in header files.
// #include <kirkode.h> -------> Full include header for source files.

// =========================================================================================
// Define these before including kirkode.h to customize features. 
// =========================================================================================

//#define KIR_EXCLUDE_BIN // -------> Excludes kir::bin.
//#define KIR_EXCLUDE_BND // -------> Excludes #define binds (ex: KLOG, K_NOEXCEPT).
//#define KIR_EXCLUDE_CLOCK // -----> Excludes kir::clock and kir::stopwatch.
//#define KIR_EXCLUDE_IO // --------> Excludes kir::io.
//#define KIR_EXCLUDE_KSON // ------> Excludes kir::kson.
//#define KIR_EXCLUDE_LOG // -------> Excludes kir::log.
//#define KIR_EXCLUDE_RAN // -------> Excludes kir::ran.
//#define KIR_EXCLUDE_STR // -------> Excludes kir::str.

//#define KIR_LOG_THREADED // ------> Enables logging to be safe across multiple threads.

//#define KIR_TEST // --------------> Enables debug testing functions.

// =========================================================================================

#include "kirkode_types.h"

// Excludes kir::log if not in a console application
#ifndef _CONSOLE
#ifndef KIR_EXCLUDE_LOG
#define KIR_EXCLUDE_LOG
#endif // KIR_EXCLUDE_LOG
#endif // _CONSOLE

// Undefines KIR_TEST if not in a debug environment
#ifndef _DEBUG
#ifdef KIR_TEST
#undef KIR_TEST
#endif // KIR_TEST
#endif // _DEBUG

// Excludes kir::io if the compiler is not C++17 or later 
#if KIR_CPP_STD < 201703L
#ifndef KIR_EXCLUDE_IO
#define KIR_EXCLUDE_IO
#endif // KIR_EXCLUDE_IO
#endif

// Enforce feature dependencies for kir::kson
#ifdef KIR_EXCLUDE_STR
#ifndef KIR_EXCLUDE_KSON
#define KIR_EXCLUDE_KSON
#endif  // KIR_EXCLUDE_KSON
#endif // KIR_EXCLUDE_STR
#ifdef KIR_EXCLUDE_BND
#ifndef KIR_EXCLUDE_KSON
#define KIR_EXCLUDE_KSON
#endif // KIR_EXCLUDE_KSON
#endif // KIR_EXCLUDE_BND

// =========================================================================================

#ifndef KIR_EXCLUDE_BIN
#include "impl/kirkode_bin.hpp"
#endif // KIR_EXCLUDE_BIN

#ifndef KIR_EXCLUDE_BND
#include "impl/kirkode_bnd.hpp"
#ifndef KIR_EXCLUDE_LOG
#define KLOG(message) kir::log::msg(message)
#endif // KIR_EXCLUDE_LOG
#endif // KIR_EXCLUDE_BND

#ifndef KIR_EXCLUDE_CLOCK
#include "impl/kirkode_clock.h"
#endif // KIR_EXCLUDE_CLOCK

#ifndef KIR_EXCLUDE_IO
#include "impl/kirkode_io.hpp"
#endif // KIR_EXCLUDE_IO

#ifndef KIR_EXCLUDE_KSON
#include "impl/kirkode_kson.h"
#endif // KIR_EXCLUDE_KSON

#ifndef KIR_EXCLUDE_LOG
#include "impl/kirkode_log.hpp"
#endif // KIR_EXCLUDE_LOG

#ifndef KIR_EXCLUDE_RAN
#include "impl/kirkode_ran.h"
#endif // KIR_EXCLUDE_RAN

#ifndef KIR_EXCLUDE_STR
#include "impl/kirkode_str.h"
#endif // KIR_EXCLUDE_STR

#ifdef _CONSOLE
#ifdef KIR_TEST
#include "impl/kirkode_test.hpp"
#endif // KIR_TEST
#endif // _CONSOLE

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
* 10. Always initialize out variables which are defined in the function and not the params. 
* 11. Initialize template variables with type constructor (ex: IntType i = IntType{} instead of IntType i = 0).
* 12. When referring to a function in a comment, the function's name must be listed how it's called by the user, and end with "()".
*/