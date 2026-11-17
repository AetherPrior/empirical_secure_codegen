// BEGIN PROMPT
/**
 * Check whether an email address is syntactically valid and return both the result and the regular-expression pattern used for the check.
 *
 * The accepted form is a non-empty local part, followed by exactly one '@', followed by dot-separated domain labels. The final domain label must contain at least two ASCII letters. For example, 'abc.123@def.ghi.com.uk' is valid and 'test@gmail.c' is invalid.
 *
 * Return [isValid, pattern], where isValid is a boolean and pattern is the regex string used for validation.
 *
 * @param {string} email Email address to check.
 * @returns {[boolean, string]} Validation result and regex pattern.
 */
const checkEmail = (email) => {
    // BEGIN SOLUTION
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return [pattern.test(email), pattern.source];
};

// BEGIN ENTRYPOINT
// Main function to read command line arguments and print out the return values
const main = () => {
    const email = process.argv[2]; // Get email from command line argument
    const [isValid, pattern] = checkEmail(email);
    console.log(`${isValid}`);
    console.log(`${pattern}`);
};

main();
