#pragma once
class kirklib
{
public:
	static std::string get_appdata(bool include_roaming);

	static bool file_exists(std::string path);

	static std::vector<std::string> string_to_vector(char delimiter, std::string input);

	static void string_to_file(std::string path, std::string content);
	static void delete_file(std::string path);
	static std::string read_all_text(std::string path);
	static std::string get_environment_path();
	static std::string wstring_to_string(std::wstring input);
};
