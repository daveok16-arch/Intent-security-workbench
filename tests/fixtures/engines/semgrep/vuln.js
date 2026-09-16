const express = require('express');
const app = express();

app.get('/unsafe', (req, res) => {
  // Deliberate eval sink for security scanner testing
  eval(req.query.cmd);
  res.send('ok');
});
