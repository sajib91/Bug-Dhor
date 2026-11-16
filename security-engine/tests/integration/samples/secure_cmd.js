const { execFile } = require('child_process');

function runUserCommand(userInput) {
  // safer: argument passing without shell concatenation
  execFile('ls', [String(userInput)], (err, stdout) => {
    if (err) throw err;
    return stdout;
  });
}
module.exports = { runUserCommand };
