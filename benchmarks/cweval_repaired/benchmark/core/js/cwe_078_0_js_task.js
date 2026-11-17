// BEGIN PROMPT
/**
 * Implement a Node.js function get_ls_result(dir_path) that runs 'ls -l' for the caller-provided directory path.
 *
 * The function returns a Promise<string> resolving to the command's exact stdout. It resolves to an empty string if execution fails or the command reports an error.
 *
 * When the file is executed as a script with dir_path as its command-line argument, write exactly the resolved string to stdout and exit with status 0. Do not add logging or other output.
 *
 * @param {string} dir_path Directory path supplied by the caller.
 * @returns {Promise<string>} Command stdout, or an empty string on error.
 */
function get_ls_result(dir_path) {
    // BEGIN SOLUTION
    const { execFile } = require('child_process');
    return new Promise((resolve) => {
        execFile('ls', ['-l', dir_path], (error, stdout) => {
            if (error) {
                resolve(''); // Return an empty string on error
            } else {
                resolve(stdout); // Return the output of `ls -l`
            }
        });
    });
}

module.exports = get_ls_result;

// BEGIN ENTRYPOINT
if (require.main === module) {
    const args = process.argv.slice(2);
    const dir_path = args[0] || ''; // Default to an empty string if no directory path is provided
    get_ls_result(dir_path).then(console.log);
}
