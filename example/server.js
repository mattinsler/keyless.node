var express = require('express')
  , Keyless = require('keyless.node')
  , keyless = Keyless({server: 'http://keyless.unified.dev', shared_key: 'fafafeefee', authorization_data: {service: 'foobar'}});

var app = express();

app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.cookieParser());
app.use(express.session({secret: 'irhe082h304ufhqu9eyft9eg'}));
app.use(keyless.middleware())
app.use(app.router);

app.get('/', keyless.protect, function(req, res) {
  res.end(JSON.stringify(req.keyless_user, null, 2));
});

app.get('/logout', keyless.logout);

app.listen(4000);
