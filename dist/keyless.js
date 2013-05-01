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
    var authenticate, redirect_without_ticket, remove_ticket_from_url, validate_ticket, validate_token, _ref;
    if (opts.server == null) {
      throw new Error('Must provide a server parameter');
    }
    opts.server = fix_server_url(opts.server);
    if ((_ref = opts.shared_key_header) == null) {
      opts.shared_key_header = 'x-keyless-sso';
    }
    remove_ticket_from_url = function(url) {
      var parsed;
      parsed = betturl.parse(url);
      delete parsed.query.auth_ticket;
      return betturl.format(parsed);
    };
    redirect_without_ticket = function(req, res, next) {
      return res.redirect(remove_ticket_from_url(req.full_url));
    };
    authenticate = function(req, res, next) {
      delete req.keyless_user;
      delete req.session.keyless_token;
      return res.redirect(opts.server + '/login?callback=' + encodeURIComponent(remove_ticket_from_url(req.full_url)));
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
          return authenticate(req, res, next);
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
        if (req.query.auth_ticket != null) {
          return redirect_without_ticket(req, res, next);
        }
        return next();
      });
    };
    return {
      protect: function(req, res, next) {
        var _ref1;
        req.query = betturl.parse(req.url).query;
        req.resolved_protocol = (_ref1 = req.get('x-forwarded-proto')) != null ? _ref1 : req.protocol;
        req.full_url = req.resolved_protocol + '://' + req.get('host') + req.url;
        if (req.keyless_user != null) {
          return next();
        }
        if (req.query.auth_token != null) {
          return validate_token(req, res, next, req.query.auth_token);
        }
        if (req.session.keyless_token != null) {
          return validate_token(req, res, next, req.session.keyless_token);
        }
        if (req.query.auth_ticket != null) {
          return validate_ticket(req, res, next, req.query.auth_ticket);
        }
        return authenticate(req, res, next);
      },
      logout: function(req, res, next) {
        var url;
        delete req.keyless_user;
        delete req.session.keyless_token;
        url = opts.server + '/logout';
        if (opts.on_logout != null) {
          url += '?callback=' + encodeURIComponent(url);
        }
        return res.redirect(url);
      }
    };
  };

}).call(this);
