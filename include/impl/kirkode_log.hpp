#pragma once

#include <string> // std::string.
#include <exception> // std::exception.
#include <iostream>

#ifdef KIR_LOG_THREADED
#include <mutex>
#endif

namespace kir {
	/**
	 * \brief ANSI text formatting styles for console output.
	 * Controls visual styling of printed text such as bold, underline, and italic.
	 */
	enum class log_sty : uint8_t {
		NONE = 0,
		BOLD = 1, DIM = 2, ITALIC = 3, UNDERLINE = 4,
		BLINK = 5, REVERSE = 7, HIDDEN = 8, STRIKETHROUGH = 9
	};

	/**
	 * \brief Foreground (text) colors for console output.
	 * Represents standard and bright ANSI terminal text colors.
	 */
	enum class log_clr : uint8_t {
		NONE = 0,
		BLACK = 30, RED = 31, GREEN = 32, YELLOW = 33,
		BLUE = 34, MAGENTA = 35, CYAN = 36, WHITE = 37,
		BRIGHT_BLACK = 90, BRIGHT_RED = 91, BRIGHT_GREEN = 92, BRIGHT_YELLOW = 93,
		BRIGHT_BLUE = 94, BRIGHT_MAGENTA = 95, BRIGHT_CYAN = 96, BRIGHT_WHITE = 97
	};

	/**
	 * \brief Background colors for console output text.
	 * Defines ANSI color codes used to set the background behind printed text.
	 */
	enum class log_bkg : uint8_t {
		NONE = 0,
		BLACK = 40, RED = 41, GREEN = 42, YELLOW = 43,
		BLUE = 44, MAGENTA = 45, CYAN = 46, WHITE = 47,
		BRIGHT_BLACK = 100, BRIGHT_RED = 101, BRIGHT_GREEN = 102, BRIGHT_YELLOW = 103,
		BRIGHT_BLUE = 104, BRIGHT_MAGENTA = 105, BRIGHT_CYAN = 106, BRIGHT_WHITE = 107
	};
}

namespace kir {
	/**
	 * \brief Simple console logging utility with optional color, styling, and thread safety.
	 *
	 * The log class provides a lightweight interface for printing messages to the console.
	 * It supports:
	 *
	 * 1: Plain text logging.
	 * 2: Optional newline control.
	 * 3: ANSI-colored output with foreground/background styling.
	 * 4: Basic text styles (bold, underline, etc.).
	 * 5: Optional thread-safe logging (if KIR_LOG_THREADED is enabled).
	 *
	 * This class is entirely static and does not require instantiation.
	 */
	class log {
#ifdef KIR_LOG_THREADED
	private:
		inline static std::mutex logMutex;
#endif
	public:
		/**
		* \brief Logs a message in the console.
		*
		* \param message: String message to log.
		*/
		static void msg(const std::string& message) noexcept {
#ifdef KIR_LOG_THREADED
			std::lock_guard<std::mutex> lock(logMutex);
#endif
			std::cout << message << std::endl;
		}

		/**
		* \brief Logs a message in the console with optional new line.
		*
		* \param message: String message to log.
		* \param newLine: If true, end line after message. If false, do not end line.
		*/
		static void msg(const std::string& message, bool newLine) noexcept {
#ifdef KIR_LOG_THREADED
			std::lock_guard<std::mutex> lock(logMutex);
#endif
			std::cout << message;
			if (newLine) std::cout << std::endl;
		}

		/**
		* \brief Logs a message in the console with controls for foreground and background color,
		* text style, and whether to end with a new line or not.
		*
		* \param message: String message to log.
		* \param foreground: Color of the text.
		* \param background: Color of the background behind the text.
		* \param style: Style of the text.
		* \param newLine: If true, end line after message. If false, do not end line.
		*/
		static void msg(
			const std::string& message,
			log_clr foreground,
			log_bkg background = log_bkg::NONE,
			log_sty style = log_sty::NONE,
			bool newLine = true
		) noexcept {
#ifdef KIR_LOG_THREADED
			std::lock_guard<std::mutex> lock(logMutex);
#endif
			bool textChanged = false;
			if (foreground != log_clr::NONE) {
				std::cout << "\033[" << static_cast<uint8_t>(foreground) << 'm';
				textChanged = true;
			}
			if (background != log_bkg::NONE) {
				std::cout << "\033[" << static_cast<uint8_t>(background) << 'm';
				textChanged = true;
			}
			if (style != log_sty::NONE) {
				std::cout << "\033[" << static_cast<uint8_t>(style) << 'm';
				textChanged = true;
			}
			std::cout << message;
			if (textChanged) std::cout << "\033[0m";
			if (newLine) std::cout << std::endl;
		}

		/**
		* \brief Logs an error message and optionally the 'what()' of an exception.
		*
		* \param message: String message to log.
		* \param e: Pointer to exception.
		*/
		static void err(const std::string& message, const std::exception* e = nullptr) noexcept {
#ifdef KIR_LOG_THREADED
			std::lock_guard<std::mutex> lock(logMutex);
#endif
			std::cout << "\033[97m\033[101m" << "[ERROR] " << message;
			if (e) std::cout << e->what();
			std::cout << "\033[0m" << std::endl;
		}
	};
}
