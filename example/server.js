var express = require('express')
  , Keyless = require('../dist/keyless');

var app = express();

app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.cookieParser());
app.use(express.session({secret: 'irhe082h304ufhqu9eyft9eg'}));
app.use(app.router);

var keyless = Keyless({server: 'http://keyless.unifiedsocial.dev', shared_key: 'fafafeefee'});

app.get('/', keyless.protect, function(req, res) {
  var user = req.keyless_user;
  res.end('Hello ' + user.identity.name + '!\nYou are a ' + user.metadata.role + '\nYou have access to: ' + user.metadata.products.join(', '));
});

app.get('/logout', keyless.logout);

app.listen(4000);
