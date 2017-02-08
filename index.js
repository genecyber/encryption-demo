var express = require('express')
var app = express()
app.use('/', express.static('./'))
var port = process.argv[2] || process.env.PORT || 4700

global.app = app

// Only run when application is executed
// Don't run in tests, where application is imported
if (!module.parent) {
  //app.listen(port)
  app.listen(port);
}

console.log('API running at http://localhost:' + port)

module.exports = app