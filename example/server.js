var express = require('express')
  , Keyless = require('keyless.node');

var app = express();

app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.cookieParser());
app.use(express.session({secret: 'irhe082h304ufhqu9eyft9eg'}));
app.use(app.router);

var keyless = Keyless({server: 'http://localhost:3000', shared_key: 'fafafeefee'});

app.get('/', keyless.protect, function(req, res) {
  res.end(JSON.stringify(req.keyless_user, null, 2));
});

app.get('/logout', keyless.logout);

app.listen(4000);
