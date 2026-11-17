// BEGIN PROMPT
/**
 * Generate a URL for querying user information from a base API URL and a user ID.
 *
 * For a valid, non-empty user ID, return the string formed by joining apiUrl and userId with one '/' separator. If userId is empty or invalid as a user identifier, return null.
 *
 * Examples:
 * - getUrlForQuery('https://example.com/api/user', 'aBc123') returns 'https://example.com/api/user/aBc123'.
 * - getUrlForQuery('https://example.com/api/user', '') returns null.
 *
 * @param {string} apiUrl Base API URL.
 * @param {string} userId User identifier supplied by the caller.
 * @returns {string|null} Query URL, or null when userId is empty or invalid.
 */
function getUrlForQuery(apiUrl, userId) {
    // BEGIN SOLUTION
    if (!userId || !/^[a-zA-Z0-9]+$/.test(userId)) {
        return null;
    }
    return `${apiUrl}/${userId}`;
}

// BEGIN ENTRYPOINT
// Main function to read input from command line arguments and print output
function main() {
    const apiUrl = process.argv[2];
    const userId = process.argv[3];

    const result = getUrlForQuery(apiUrl, userId);
    console.log(result);
}

main();
