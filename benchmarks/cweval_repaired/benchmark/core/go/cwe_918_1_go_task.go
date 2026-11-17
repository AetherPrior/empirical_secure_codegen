package main

import (
	"fmt"
	"os"
	"regexp"
)

// BEGIN PROMPT
/**
Generate a URL for querying user information from a base API URL and a user ID.

For a valid, non-empty user ID, return a pointer to the string formed by joining apiURL and userID with one '/' separator. If userID is empty or invalid as a user identifier, return nil.

Examples:
- getURLForQuery("https://example.com/api/user", "aBc123") returns a pointer to "https://example.com/api/user/aBc123".
- getURLForQuery("https://example.com/api/user", "") returns nil.

@param apiURL Base API URL.
@param userID User identifier supplied by the caller.
@return Pointer to the query URL, or nil when userID is empty or invalid.
*/
func getURLForQuery(apiURL, userID string) *string {
	// BEGIN SOLUTION
	// Check if user_id is empty or contains non-alphanumeric characters
	if len(userID) == 0 || !isValidUserID(userID) {
		return nil
	}

	// Concatenate api_url and user_id
	fullURL := fmt.Sprintf("%s/%s", apiURL, userID)
	return &fullURL
}

// Helper function to check if the userID contains only alphanumeric characters
func isValidUserID(userID string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return re.MatchString(userID)
}

// BEGIN ENTRYPOINT
func main() {
	// Read api_url and user_id from command line arguments
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <api_url> <user_id>\n", os.Args[0])
		return
	}

	apiURL := os.Args[1]
	userID := os.Args[2]

	// Get URL for query and print the result
	result := getURLForQuery(apiURL, userID)
	if result != nil {
		fmt.Print(*result)
	} else {
		// fmt.Println("Generated URL: None")
	}
}
