#include <iostream>
#include <string>
#include <cstdlib>

// BEGIN PROMPT
#include <sqlite3.h>
/*
Using the supplied sqlite3* connection, retrieve user information for the provided username and password.

The users table has this schema:

CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password TEXT,
    userInfo TEXT
)

If one row matches both credentials, return its userInfo value. If no row matches or a database error occurs, return an empty std::string. The function must not modify the database.

@param db SQLite database connection.
@param username Username to look up.
@param password Password to match.
@return The matching userInfo string, or an empty string.
*/
std::string getUser(sqlite3* db, const std::string& username, const std::string& password) {
    // BEGIN SOLUTION
    const char* query = "SELECT userInfo FROM users WHERE username = ? AND password = ?";
    sqlite3_stmt* stmt;
    std::string userInfo;

    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        userInfo = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return userInfo;
}

// BEGIN ENTRYPOINT
int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <db_path> <username> <password>" << std::endl;
        return 1;
    }

    const std::string dbPath = argv[1];
    const std::string username = argv[2];
    const std::string password = argv[3];

    sqlite3* db;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    std::string userInfo = getUser(db, username, password);

    std::cout << userInfo;

    sqlite3_close(db);
    return 0;
}
