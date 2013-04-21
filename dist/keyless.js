(function() {
  var betturl, request;

  betturl = require('betturl');

  request = require('request');

  module.exports = function(opts) {
    if (opts.server == null) {
      throw new Error('');
    }
    return {
      protect: function(req, res, next) {
        var auth, url, _ref;
        if (req.session.keyless_user != null) {
          req.keyless_user = req.session.keyless_user;
          return next();
        }
        url = ((_ref = req.get('x-forwarded-protocol')) != null ? _ref : req.protocol) + '://' + req.get('host') + req.url;
        auth = function() {
          return res.redirect(opts.server + '/login?callback=' + encodeURIComponent(url));
        };
        if (req.query.ticket == null) {
          return auth();
        }
        return request({
          url: opts.server + '/validate?ticket=' + encodeURIComponent(req.query.ticket),
          pool: false,
          headers: {
            'x-keyless-sso': opts.shared_key
          }
        }, function(err, validate_res, body) {
          var parsed;
          if (err != null) {
            return next(err);
          }
          if (typeof body === 'string') {
            body = JSON.parse(body);
          }
          req.session.keyless_user = body.user;
          parsed = betturl.parse(url);
          delete parsed.query.ticket;
          url = betturl.format(parsed);
          return res.redirect(url);
        });
      },
      logout: function(req, res, next) {
        var url;
        delete req.session.keyless_user;
        url = opts.server + '/logout';
        if (opts.on_logout != null) {
          url += '?callback=' + encodeURIComponent(url);
        }
        return res.redirect(url);
      }
    };
  };

}).call(this);
