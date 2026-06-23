#pragma once

#include <string> // std::string.
#include <exception> // std::exception.
#include <iostream>

#ifdef KIR_LOG_THREADED
#include <mutex>
#endif

namespace kir {
	class log {
#ifdef KIR_LOG_THREADED
	private:
		inline static std::mutex logMutex;
#endif
	public:
		enum class text_style : uint8_t {
			NONE = 0,
			BOLD = 1, DIM = 2, ITALIC = 3, UNDERLINE = 4,
			BLINK = 5, REVERSE = 7, HIDDEN = 8, STRIKETHROUGH = 9
		};
		enum class text_color : uint8_t {
			NONE = 0,
			BLACK = 30, RED = 31, GREEN = 32, YELLOW = 33,
			BLUE = 34, MAGENTA = 35, CYAN = 36, WHITE = 37,
			BRIGHT_BLACK = 90, BRIGHT_RED = 91, BRIGHT_GREEN = 92, BRIGHT_YELLOW = 93,
			BRIGHT_BLUE = 94, BRIGHT_MAGENTA = 95, BRIGHT_CYAN = 96, BRIGHT_WHITE = 97
		};
		enum class text_background : uint8_t {
			NONE = 0,
			BLACK = 40, RED = 41, GREEN = 42, YELLOW = 43,
			BLUE = 44, MAGENTA = 45, CYAN = 46, WHITE = 47,
			BRIGHT_BLACK = 100, BRIGHT_RED = 101, BRIGHT_GREEN = 102, BRIGHT_YELLOW = 103,
			BRIGHT_BLUE = 104, BRIGHT_MAGENTA = 105, BRIGHT_CYAN = 106, BRIGHT_WHITE = 107
		};
	public:
		/**
		* Logs a message in the console.
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
		* Logs a message in the console with optional new line.
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
		* Logs a message in the console with controls for foreground and background color,
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
			text_color foreground,
			text_background background = text_background::NONE,
			text_style style = text_style::NONE,
			bool newLine = true
		) noexcept {
#ifdef KIR_LOG_THREADED
			std::lock_guard<std::mutex> lock(logMutex);
#endif
			bool textChanged = false;
			if (foreground != text_color::NONE) {
				std::cout << "\033[" << static_cast<uint8_t>(foreground) << 'm';
				textChanged = true;
			}
			if (background != text_background::NONE) {
				std::cout << "\033[" << static_cast<uint8_t>(background) << 'm';
				textChanged = true;
			}
			if (style != text_style::NONE) {
				std::cout << "\033[" << static_cast<uint8_t>(style) << 'm';
				textChanged = true;
			}
			std::cout << message;
			if (textChanged) std::cout << "\033[0m";
			if (newLine) std::cout << std::endl;
		}

		/**
		* Logs an error message and optionally the 'what()' of an exception.
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
