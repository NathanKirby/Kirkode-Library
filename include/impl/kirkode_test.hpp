#pragma once
#ifdef KIR_TEST
#include "kirkode_types.h"

namespace kir {
	namespace test {
		/**
		* \brief Logs a condition with its name.
		* 
		* \return true if condition is true, false otherwise.
		*/
		static bool check_condition(const bool condition, const std::string& name) noexcept {
#ifndef KIR_EXCLUDE_LOG
			if (condition) {
				kir::log::msg("[PASS] " + name, kir::log_clr::GREEN);
			}
			else {
				kir::log::err("[FAIL] " + name);
			}
#endif			
			return condition;
		}

		/**
		 * \brief Tests functionality of kir::flag_poll.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_flag() noexcept {
			bool ok = true;
			kir::flag_poll<> fp;
			ok &= check_condition(fp.get() == 0, "flag_poll default empty");
			ok &= check_condition(fp.set_flag(kir::flag_bit::FLAG_0), "flag_poll set_flag FLAG_0");
			ok &= check_condition(fp.is_flag_set(kir::flag_bit::FLAG_0), "flag_poll is_flag_set FLAG_0");
			ok &= check_condition(!fp.is_flag_set(kir::flag_bit::FLAG_1), "flag_poll not set FLAG_1");
			ok &= check_condition(fp.clear_flag(kir::flag_bit::FLAG_0), "flag_poll clear_flag");
			ok &= check_condition(!fp.is_flag_set(kir::flag_bit::FLAG_0), "flag_poll cleared");
			fp.set_flag(kir::flag_bit::FLAG_3);
			fp.clear_all();
			ok &= check_condition(fp.get() == 0, "flag_poll clear_all");
			kir::flag_poll<uint8_t> small;
			ok &= check_condition(!small.set_flag(kir::flag_bit::FLAG_8), "flag_poll out-of-range rejected");
			return ok;
		}
	}
}

#ifndef KIR_EXCLUDE_BIN
#include "impl/kirkode_bin.hpp"
namespace kir {
	namespace test {
		/**
		 * \brief Tests functionality of kir::bin.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_bin() noexcept {
			bool ok = true;
			kir::bytes buf;
			ok &= check_condition(kir::bin::pack_int(buf, int32_t{ -123456 }), "bin::pack_int signed");
			ok &= check_condition(kir::bin::pack_int(buf, uint16_t{ 0xABCD }), "bin::pack_int unsigned");
			ok &= check_condition(kir::bin::pack_float(buf, 3.14159f), "bin::pack_float");
			ok &= check_condition(kir::bin::pack_str(buf, std::string("hello")), "bin::pack_str");

			size_t off = 0;
			int32_t i32 = 0;
			ok &= check_condition(kir::bin::unpack_int_at(off, buf, i32) && i32 == -123456, "bin::unpack_int_at signed");
			uint16_t u16 = 0;
			ok &= check_condition(kir::bin::unpack_int_at(off, buf, u16) && u16 == 0xABCD, "bin::unpack_int_at unsigned");
			float f = 0.f;
			ok &= check_condition(kir::bin::unpack_float_at(off, buf, f) && std::fabs(f - 3.14159f) < 0.0001f, "bin::unpack_float_at");
			std::string s;
			ok &= check_condition(kir::bin::unpack_str_at(off, buf, s) && s == "hello", "bin::unpack_str_at");

			kir::bytes buf2(16, 0);
			ok &= check_condition(kir::bin::pack_int_at(buf2, 0, int16_t{ 42 }), "bin::pack_int_at fixed");
			ok &= check_condition(kir::bin::unpack_int_at_r<int16_t>(buf2, 0) == 42, "bin::unpack_int_at_r");
			size_t o2 = 0;
			ok &= check_condition(kir::bin::pack_float_at(o2, buf2, 2.5f), "bin::pack_float_at streaming");
			ok &= check_condition(o2 == sizeof(float), "bin pack_float_at advanced offset");
			float f2 = kir::bin::unpack_float_at_r(buf2, 0);
			ok &= check_condition(std::fabs(f2 - 2.5f) < 0.0001f, "bin::unpack_float_at_r");

			struct TestPod { int a; float b; };
			TestPod pod{ 7, 1.5f };
			kir::bytes buf3(32, 0);
			size_t o3 = 0;
			ok &= check_condition(kir::bin::pack_class_at(o3, buf3, pod), "bin::pack_class_at");
			TestPod pod2{};
			size_t o4 = 0;
			ok &= check_condition(kir::bin::unpack_class_at(o4, buf3, pod2) && pod2.a == 7 && std::fabs(pod2.b - 1.5f) < 0.0001f, "bin::unpack_class_at");

			try {
				const int32_t e = kir::bin::unpack_int_at_e<int32_t>(buf, 0);
				ok &= check_condition(e == -123456, "bin::unpack_int_at_e");
			}
			catch (...) {
				ok &= check_condition(false, "bin::unpack_int_at_e threw unexpectedly");
			}
			return ok;
		}
	}
} 
#endif // KIR_EXCLUDE_BIN

#ifndef KIR_EXCLUDE_BND
#include "impl/kirkode_bnd.hpp"
namespace kir {
	namespace test {
		/**
		 * \brief Tests functionality of all binds.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_bnd() noexcept {
			bool ok = true;
			ok &= check_condition(K_NOEXCEPT(1 + 1), "K_NOEXCEPT success");
			ok &= check_condition(!K_NOEXCEPT(throw 1), "K_NOEXCEPT catches");
			int x = 0;
			K_NOEXCEPT_H(x = 5, x = -1);
			ok &= check_condition(x == 5, "K_NOEXCEPT_H success path");
			K_NOEXCEPT_H(throw 1, x = 99);
			ok &= check_condition(x == 99, "K_NOEXCEPT_H exception path");
			return ok;
		}
	}
}
#endif // KIR_EXCLUDE_BND

#ifndef KIR_EXCLUDE_CLOCK
#include "impl/kirkode_clock.h"
namespace kir {
	namespace test {		
		/**
		 * \brief Tests functionality of kir::clock and kir::stopwatch.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_clock() noexcept {
			bool ok = true;
			const kir::time t0 = kir::clock::get_epoch();
			ok &= check_condition(t0 > 0, "clock::get_epoch() > 0");
			const kir::time since = kir::clock::time_since(t0);
			ok &= check_condition(since >= 1, "clock::time_since() immediate");
			ok &= check_condition(kir::clock::stopwatch_start(), "clock::stopwatch_start()");
			ok &= check_condition(kir::clock::stopwatch_running(), "clock::stopwatch_running()");
			kir::time elapsed = 0;

			for (volatile int i = 0; i < 100000; ++i) {}
			ok &= check_condition(kir::clock::stopwatch_stop(elapsed), "clock::stopwatch_stop()");
			ok &= check_condition(elapsed >= 0, "clock stopwatch elapsed");
			ok &= check_condition(!kir::clock::stopwatch_running(), "clock stopwatch stopped");

			kir::stopwatch sw;
			ok &= check_condition(sw.running(), "stopwatch starts running");
			const kir::time c1 = sw.check();
			ok &= check_condition(c1 >= 0, "stopwatch::check()");
			const kir::time r1 = sw.restart();
			ok &= check_condition(r1 >= 0, "stopwatch::restart()");
			const kir::time s1 = sw.stop();
			ok &= check_condition(s1 >= 0, "stopwatch::stop()");
			ok &= check_condition(!sw.running(), "stopwatch stopped");
			return ok;
		}
	}
}
#endif // KIR_EXCLUDE_CLOCK

#ifndef KIR_EXCLUDE_IO
#include "impl/kirkode_io.hpp"
namespace kir {
	namespace test {		
		/**
		 * \brief Tests functionality of kir::io.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_io() noexcept {
			bool ok = true;
			const std::string dir = "kirkode_test_tmp_dir";
			const std::string file = dir + "/test.bin";
			const std::string file2 = dir + "/test2.txt";
			const std::string file3 = dir + "/renamed.txt";

			kir::io::remove_directory(dir);

			ok &= check_condition(kir::io::touch_directory(dir), "io::touch_directory");
			ok &= check_condition(kir::io::directory_exists(dir), "io::directory_exists");
			ok &= check_condition(kir::io::touch_file(file), "io::touch_file");
			ok &= check_condition(kir::io::file_exists(file), "io::file_exists");

			kir::bytes binData = { 1, 2, 3, 4, 5 };
			ok &= check_condition(kir::io::write_binary(file, binData), "io::write_binary");
			kir::bytes readBin;
			ok &= check_condition(kir::io::read_binary(file, readBin) && readBin == binData, "io::read_binary");

			ok &= check_condition(kir::io::write_text(file2, "hello world"), "io::write_text");
			std::string text;
			ok &= check_condition(kir::io::read_text(file2, text) && text == "hello world", "io::read_text");

			ok &= check_condition(kir::io::rename(file2, "renamed.txt"), "io::rename");
			ok &= check_condition(kir::io::file_exists(file3), "io::rename result exists");
			ok &= check_condition(kir::io::move(file3, dir + "/moved.txt"), "io::move");
			ok &= check_condition(kir::io::file_exists(dir + "/moved.txt"), "io::move result exists");

			ok &= check_condition(kir::io::remove_file(file), "io::remove_file");
			ok &= check_condition(kir::io::remove_directory(dir), "io::remove_directory");
			ok &= check_condition(!kir::io::directory_exists(dir), "io directory cleaned");
			return ok;
		}
	}
}
#endif // KIR_EXCLUDE_IO

#ifndef KIR_EXCLUDE_KSON
#include "impl/kirkode_kson.h"
namespace kir {
	namespace test {		
		/**
		 * \brief Tests functionality of kir::kson.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_kson() noexcept {
			bool ok = true;
			ok &= check_condition(kir::kson::is_legal_member_name("valid_name 1"), "kson::is_legal_member_name good");
			ok &= check_condition(!kir::kson::is_legal_member_name("bad!"), "kson::is_legal_member_name reject");
			ok &= check_condition(!kir::kson::is_legal_member_name(""), "kson::is_legal_member_name empty");

			kir::kson obj;
			ok &= check_condition(obj.reserve(4), "kson::reserve");
			ok &= check_condition(obj.add_member("count", kir::kson_type::INT32, "42"), "kson::add_member typed");
			ok &= check_condition(obj.add_member("label", "hello"), "kson::add_member untyped");
			ok &= check_condition(obj.get_member_count() == 2, "kson::get_member_count");
			const kir::kson_member* m = obj.get_member("count");
			ok &= check_condition(m != nullptr && m->content == "42" && m->expected_type == kir::kson_type::INT32, "kson::get_member");
			ok &= check_condition(obj.get_members().size() == 2, "kson::get_members");

			std::string serialized;
			ok &= check_condition(kir::kson::serialize(obj, serialized) && !serialized.empty(), "kson::serialize");
			kir::kson obj2;
			ok &= check_condition(kir::kson::deserialize(serialized, obj2), "kson::deserialize");
			ok &= check_condition(obj2.get_member_count() == 2, "kson deserialize member count");
			const kir::kson_member* m2 = obj2.get_member("label");
			ok &= check_condition(m2 != nullptr && m2->content == "hello", "kson deserialize content");

			obj.clear();
			ok &= check_condition(obj.get_member_count() == 0, "kson::clear");
			return ok;
		}
	}
}
#endif // KIR_EXCLUDE_KSON

#ifndef KIR_EXCLUDE_LOG
#include "impl/kirkode_log.hpp"
namespace kir {
	namespace test {		
		/**
		 * \brief Tests functionality of kir::log.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_log() noexcept {
			kir::log::msg("plain message");
			kir::log::msg("no newline", false);
			kir::log::msg(" (continued)");
			kir::log::msg("colored green bold", kir::log_clr::GREEN, kir::log_bkg::NONE, kir::log_sty::BOLD);
			kir::log::msg("cyan on black", kir::log_clr::CYAN, kir::log_bkg::BLACK);
			kir::log::err("sample error message (expected)");
			return check_condition(true, "log functions executed without crash");
		}
	}
}
#endif // KIR_EXCLUDE_KSON

#ifndef KIR_EXCLUDE_RAN
#include "impl/kirkode_ran.h"
namespace kir {
	namespace test {		
		/**
		 * \brief Tests functionality of kir::ran.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_ran() noexcept {
			bool ok = true;
			const int r1 = kir::ran::random_int<int>(-10, 10);
			ok &= check_condition(r1 >= -10 && r1 <= 10, "ran::random_int range signed");
			const uint32_t r2 = kir::ran::random_int<uint32_t>(5, 15);
			ok &= check_condition(r2 >= 5 && r2 <= 15, "ran::random_int range unsigned (min respected)");
			const float rf = kir::ran::random_float(0.f, 1.f);
			ok &= check_condition(rf >= 0.f && rf <= 1.f, "ran::random_float range");
			const kir::bytes rb = kir::ran::random_bytes(16);
			ok &= check_condition(rb.size() == 16, "ran::random_bytes size");
			return ok;
		}
	}
}
#endif // KIR_EXCLUDE_RAN

#ifndef KIR_EXCLUDE_STR
#include "impl/kirkode_str.h"
namespace kir {
	namespace test {
		/**
		 * \brief Tests functionality of kir::str.
		 *
		 * \return true if tests successful, false otherwise.
		 */
		static bool test_str() noexcept {
			bool ok = true;
			ok &= check_condition(kir::str::add_whitelist("abc123", 1), "str::add_whitelist");
			std::string s1 = "aX2bY3cZ";
			ok &= check_condition(kir::str::clean_with_whitelist(s1, 1) && s1 == "a2b3c", "str::clean_with_whitelist");
			ok &= check_condition(kir::str::add_blacklist("XYZ", 2), "str::add_blacklist");
			std::string s2 = "aXbYcZ";
			ok &= check_condition(kir::str::clean_with_blacklist(s2, 2) && s2 == "abc", "str::clean_with_blacklist");

			std::string s3 = "Hello 123!\n\t";
			size_t trimmed = 0;
			ok &= check_condition(kir::str::clean_with_preset(s3, kir::str::str_preset::ALPHANUMERIC, &trimmed) && s3 == "Hello123", "str::clean_with_preset ALPHANUMERIC");

			std::string b64 = "Hello";
			ok &= check_condition(kir::str::base64_encode(b64) && b64 == "SGVsbG8=", "str::base64_encode");
			ok &= check_condition(kir::str::is_valid_base64(b64, b64.size()), "str::is_valid_base64");
			ok &= check_condition(kir::str::base64_decode(b64) && b64 == "Hello", "str::base64_decode");

			std::string b64u = "Hello+";
			ok &= check_condition(kir::str::base64url_encode(b64u), "str::base64url_encode");
			ok &= check_condition(kir::str::is_valid_base64url(b64u, b64u.size()), "str::is_valid_base64url");
			ok &= check_condition(kir::str::base64url_decode(b64u) && b64u == "Hello+", "str::base64url_decode");

			ok &= check_condition(kir::str::is_digits_only("12345"), "str::is_digits_only positive");
			ok &= check_condition(kir::str::is_digits_only("-42", true), "str::is_digits_only signed");
			ok &= check_condition(!kir::str::is_digits_only("12a"), "str::is_digits_only reject");

			int32_t iv = 0;
			ok &= check_condition(kir::str::to_int("-99", iv) && iv == -99, "str::to_int");
			std::string os;
			ok &= check_condition(kir::str::convert_from_int(12345, os) && os == "12345", "str::convert_from_int positive");
			ok &= check_condition(kir::str::convert_from_int(-7, os) && os == "-7", "str::convert_from_int negative");
			ok &= check_condition(kir::str::convert_from_int(0, os) && os == "0", "str::convert_from_int zero");
			ok &= check_condition(kir::str::convert_from_enum(kir::kson_type::FLOAT, os) && !os.empty(), "str::convert_from_enum");
			return ok;
		}
	}
}
#endif // KIR_EXCLUDE_STR

namespace kir {
	namespace test {
		static bool run_all() noexcept {
#ifndef KIR_EXCLUDE_LOG
			kir::log::msg("=== Kirkode library self-test (v" KIR_VERSION_STRING ") ===", kir::log_clr::BRIGHT_CYAN, kir::log_bkg::NONE, kir::log_sty::BOLD);
#endif // KIR_EXCLUDE_LOG
			bool all = true;
			all &= test_flag();
#ifndef KIR_EXCLUDE_BIN
			all &= test_bin();
#endif // KIR_EXCLUDE_BIN
#ifndef KIR_EXCLUDE_BND
			all &= test_bnd();
#endif // KIR_EXCLUDE_BND
#ifndef KIR_EXCLUDE_CLOCK
			all &= test_clock();
#endif // KIR_EXCLUDE_CLOCK
#ifndef KIR_EXCLUDE_IO
			all &= test_io();
#endif // KIR_EXCLUDE_IO
#ifndef KIR_EXCLUDE_KSON
			all &= test_kson();
#endif // KIR_EXCLUDE_KSON
#ifndef KIR_EXCLUDE_LOG
			all &= test_log();
#endif // KIR_EXCLUDE_LOG
#ifndef KIR_EXCLUDE_RAN
			all &= test_ran();
#endif // KIR_EXCLUDE_RAN
#ifndef KIR_EXCLUDE_STR
			all &= test_str();
#endif // KIR_EXCLUDE_STR
#ifndef KIR_EXCLUDE_LOG
			if (all) {
				kir::log::msg("=== ALL TESTS PASSED ===", kir::log_clr::BRIGHT_GREEN, kir::log_bkg::NONE, kir::log_sty::BOLD);
			}
			else {
				kir::log::err("=== SOME TESTS FAILED ===");
			}
#endif // KIR_EXCLUDE_LOG
			return all;
		}
	}
}
#endif // KIR_TEST