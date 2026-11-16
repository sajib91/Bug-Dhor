const { exec } = require('child_process');

function runUserCommand(userInput) {
  // intentionally vulnerable: command injection
  exec('ls ' + userInput, (err, stdout) => {
    if (err) throw err;
    return stdout;
  });
}
module.exports = { runUserCommand };
