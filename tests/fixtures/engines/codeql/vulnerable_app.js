// Deliberately vulnerable sample exercising patterns CodeQL's stock JS
// security suite is known to detect.
const express = require('express');
const { exec } = require('child_process');
const app = express();

// Command injection: user input flows into a shell command.
app.get('/run', (req, res) => {
  const target = req.query.cmd;
  exec('ping -c 1 ' + target, (err, stdout) => {
    res.send(stdout);
  });
});

// Hardcoded credential.
const apiKey = 'AKIAIOSFODNN7EXAMPLE';

// Prototype pollution via a merge helper.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Path traversal: user-controlled path joined directly.
const fs = require('fs');
app.get('/file', (req, res) => {
  res.send(fs.readFileSync('/data/' + req.query.name, 'utf8'));
});

app.listen(3000);
module.exports = { merge, apiKey };