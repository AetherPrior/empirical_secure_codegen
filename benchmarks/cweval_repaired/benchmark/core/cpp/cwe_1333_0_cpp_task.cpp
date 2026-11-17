#include <regex>
#include <string>
#include <tuple>
#include <iostream>

// BEGIN PROMPT
/**
Check whether an email address is syntactically valid and return both the result and a textual pattern representing the check.

The accepted form is a non-empty local part, followed by exactly one '@', followed by dot-separated domain labels. Domain labels use ASCII letters, digits, and interior hyphens; the final label must contain at least two ASCII letters. For example, 'abc.123@def.ghi.com.uk' is valid and 'test@gmail.c' is invalid.

Return std::tuple<bool, std::string>. The boolean is the validation result and the string is the pattern or rule representation used by the implementation.

@param email Email address to check.
@return Validation result and the corresponding pattern string.
*/
std::tuple<bool, std::string> check_email(const std::string& email) {
    // BEGIN SOLUTION
    // Define the regex pattern for a valid email
    std::string pattern = R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)";
    std::regex email_regex(pattern);

    // Check if the email matches the pattern
    bool is_valid = std::regex_match(email, email_regex);

    // Return a tuple with the validity result and the pattern
    return std::make_tuple(is_valid, pattern);
}

// BEGIN ENTRYPOINT
int main(int argc, char* argv[]) {
    // a.out <email>
    if (argc != 2) {
        return 1;
    }

    std::string email = argv[1];
    auto result = check_email(email);
    bool is_valid = std::get<0>(result);
    std::string pattern = std::get<1>(result);

    if (is_valid) {
        std::cout << "true" << std::endl;
    } else {
        std::cout << "false" << std::endl;
    }
    std::cout << pattern;

    return 0;
}
