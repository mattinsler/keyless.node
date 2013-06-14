(function() {
  var betturl, fix_server_url, request;

  betturl = require('betturl');

  request = require('request');

  fix_server_url = function(url) {
    var parsed, _ref;
    parsed = betturl.parse(url);
    if ((_ref = parsed.protocol) == null) {
      parsed.protocol = 'http';
    }
    parsed.query = {};
    parsed.hash = '';
    url = betturl.format(parsed);
    return url.replace(/\/+$/, '');
  };

  module.exports = function(opts) {
    var authenticate, clear_keyless_data, get_user, logout, obj, redirect_without_ticket, remove_ticket_token_from_url, validate_ticket, validate_token, _ref, _ref1, _ref2;
    if (opts.server == null) {
      throw new Error('Must provide a server parameter');
    }
    opts.server = fix_server_url(opts.server);
    if ((_ref = opts.shared_key_header) == null) {
      opts.shared_key_header = 'x-keyless-sso';
    }
    if ((_ref1 = opts.auth_token_querystring_param) == null) {
      opts.auth_token_querystring_param = 'auth_token';
    }
    if ((_ref2 = opts.auth_token_header_param) == null) {
      opts.auth_token_header_param = 'x-keyless-token';
    }
    remove_ticket_token_from_url = function(url) {
      var parsed;
      parsed = betturl.parse(url);
      delete parsed.query.auth_ticket;
      delete parsed.query[opts.auth_token_querystring_param];
      return betturl.format(parsed);
    };
    redirect_without_ticket = function(req, res, next) {
      return res.redirect(remove_ticket_token_from_url(req.keyless.client.full_url));
    };
    clear_keyless_data = function(req) {
      delete req.keyless_user;
      return delete req.session.keyless_token;
    };
    authenticate = function(req, res, next) {
      clear_keyless_data(req);
      return res.redirect(opts.server + '/login?callback=' + encodeURIComponent(remove_ticket_token_from_url(req.keyless.client.full_url)));
    };
    validate_ticket = function(req, res, next, ticket) {
      var headers;
      headers = {
        'Accept': 'application/json'
      };
      headers[opts.shared_key_header] = opts.shared_key;
      return request({
        url: opts.server + '/validate',
        qs: {
          ticket: ticket
        },
        pool: false,
        headers: headers
      }, function(err, validate_res, body) {
        var status_class;
        if (err != null) {
          return next(err);
        }
        status_class = parseInt(validate_res.statusCode / 100);
        if (status_class !== 2) {
          return authenticate(req, res, next);
        }
        try {
          if (typeof body === 'string') {
            body = JSON.parse(body);
          }
        } catch (e) {
          return next(e);
        }
        req.session.keyless_token = body.token;
        return redirect_without_ticket(req, res, next);
      });
    };
    validate_token = function(req, res, next, token) {
      var headers, query;
      headers = {
        'Accept': 'application/json'
      };
      headers[opts.shared_key_header] = opts.shared_key;
      query = {
        token: token
      };
      if (opts.authorization_data != null) {
        query.authorization_data = JSON.stringify(opts.authorization_data);
      }
      return request({
        url: opts.server + '/validate',
        qs: query,
        pool: false,
        headers: headers
      }, function(err, validate_res, body) {
        var status_class;
        if (err != null) {
          return next(err);
        }
        status_class = parseInt(validate_res.statusCode / 100);
        if (status_class !== 2) {
          return logout(req, res, next);
        }
        try {
          if (typeof body === 'string') {
            body = JSON.parse(body);
          }
        } catch (e) {
          return next(e);
        }
        req.keyless_user = body.user;
        req.session.keyless_token = token;
        if (req.keyless.client.query.auth_ticket != null) {
          return redirect_without_ticket(req, res, next);
        }
        return get_user(req, res, next);
      });
    };
    logout = function(req, res, next) {
      var url;
      clear_keyless_data(req);
      url = opts.server + '/logout';
      if (opts.on_logout != null) {
        url += '?callback=' + encodeURIComponent(remove_ticket_token_from_url(opts.on_logout));
      }
      return res.redirect(url);
    };
    get_user = function(req, res, next) {
      if (!((req.keyless_user != null) && (opts.get_user_from_keyless_user != null) && typeof opts.get_user_from_keyless_user === 'function')) {
        return next();
      }
      return opts.get_user_from_keyless_user(req.keyless_user, function(err, user) {
        if (err != null) {
          return next(err);
        }
        req.user = user;
        return next();
      });
    };
    obj = {
      opts: opts,
      middleware: function() {
        return function(req, res, next) {
          var _base, _ref3, _ref4, _ref5;
          if ((_ref3 = req.keyless) == null) {
            req.keyless = {};
          }
          if ((_ref4 = (_base = req.keyless).client) == null) {
            _base.client = {};
          }
          req.keyless.client.query = betturl.parse(req.url).query;
          req.keyless.client.resolved_protocol = (_ref5 = req.get('x-forwarded-proto')) != null ? _ref5 : req.protocol;
          req.keyless.client.full_url = req.keyless.client.resolved_protocol + '://' + req.get('host') + req.url;
          if (req.keyless_user != null) {
            return get_user(req, res, next);
          }
          if (req.keyless.client.query[opts.auth_token_querystring_param] != null) {
            return validate_token(req, res, next, req.keyless.client.query[opts.auth_token_querystring_param]);
          }
          if (req.get(opts.auth_token_header_param) != null) {
            return validate_token(req, res, next, req.get(opts.auth_token_header_param));
          }
          if (req.session.keyless_token != null) {
            return validate_token(req, res, next, req.session.keyless_token);
          }
          if (req.keyless.client.query.auth_ticket != null) {
            return validate_ticket(req, res, next, req.keyless.client.query.auth_ticket);
          }
          return next();
        };
      },
      protect: function(req, res, next) {
        var _ref3;
        if (((_ref3 = req.keyless) != null ? _ref3.client : void 0) == null) {
          return next(new Error('Be sure to use the keyless.middleware() in your middleware stack'));
        }
        if (req.keyless_user != null) {
          return next();
        }
        return authenticate(req, res, next);
      },
      logout: logout
    };
    obj.__defineSetter__('get_user_from_keyless_user', function(value) {
      return opts.get_user_from_keyless_user = value;
    });
    return obj;
  };

}).call(this);
