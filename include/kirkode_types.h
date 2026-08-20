#pragma once

#include <cstdint>
#include <vector>

#define KIR_VERSION_MAJOR 2
#define KIR_VERSION_MINOR 8
#define KIR_VERSION_PATCH 0
#define KIR_VERSION_STRING "2.8"

#ifdef _MSVC_LANG
#define KIR_CPP_STD _MSVC_LANG
#else
#ifdef __cplusplus
#define KIR_CPP_STD __cplusplus
#else
#define KIR_CPP_STD 0L
#endif // __cplusplus
#endif // _MSVC_LANG

namespace kir {
	/**
	 * \brief Alias for a single raw byte.
	 *
	 * Represents an 8-bit unsigned value used for low-level binary operations,
	 * such as serialization, memory manipulation, and network packet construction.
	 */
	typedef std::uint8_t byte;

	/**
	 * \brief Dynamic byte buffer.
	 *
	 * Represents a contiguous sequence of raw bytes.
	 * Commonly used as the primary buffer type for binary serialization
	 * and deserialization routines in this library.
	 *
	 * Typical usage includes:
	 * 1: Encoding integers and floating-point values.
	 * 2: Building network packets (e.g., UDP payloads).
	 * 3: Reading/writing binary file data.
	 */
	typedef std::vector<byte> bytes;

	/**
	 * \brief Millisecond-based timestamp type.
	 *
	 * Represents time values in milliseconds since an implementation-defined epoch.
	 * Used by timing utilities such as stopwatches and clocks.
	 *
	 * This type is intended for:
	 * 1: Measuring elapsed time.
	 * 2: Timestamping events.
	 * 3: Performance timing and profiling.
	 */
	typedef std::uint64_t time;

	/**
	* \brief Unsigned 4-byte value for size/length used throughout KirKode library.
	*/
	typedef std::uint32_t size;
}