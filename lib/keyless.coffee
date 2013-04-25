betturl = require 'betturl'
request = require 'request'

# Opts are:
# - server
# - shared_key
# - on_logout
# - shared_key_header

fix_server_url = (url) ->
  parsed = betturl.parse(url)
  parsed.protocol ?= 'http'
  parsed.query = {}
  parsed.hash = ''
  url = betturl.format(parsed)
  url.replace(/\/+$/, '')

module.exports = (opts) ->
  throw new Error('Must provide a server parameter') unless opts.server?
  opts.server = fix_server_url(opts.server)
  
  opts.shared_key_header ?= 'x-keyless-sso'
  
  redirect_without_ticket = (req, res, next) ->
    parsed = betturl.parse(req.full_url)
    delete parsed.query.ticket
    res.redirect(betturl.format(parsed))
  
  authenticate = (req, res, next) ->
    delete req.keyless_user
    delete req.session.keyless_token
    res.redirect(opts.server + '/login?callback=' + encodeURIComponent(req.full_url))
  
  validate_ticket = (req, res, next, ticket) ->
    headers = {
      'Accept': 'application/json'
    }
    headers[opts.shared_key_header] = opts.shared_key
    request {
      url: opts.server + '/validate'
      qs:
        ticket: ticket
      pool: false
      headers: headers
    }, (err, validate_res, body) ->
      return next(err) if err?
      return authenticate(req, res, next) if validate_res.statusCode is 401
      
      try
        body = JSON.parse(body) if typeof body is 'string'
      catch e
        return next(e)
      req.session.keyless_token = body.token
      redirect_without_ticket(req, res, next)
  
  validate_token = (req, res, next, token) ->
    headers = {
      'Accept': 'application/json'
    }
    headers[opts.shared_key_header] = opts.shared_key
    query = {token: token}
    query.authorization_data = JSON.stringify(opts.authorization_data) if opts.authorization_data?
    request {
      url: opts.server + '/validate'
      qs: query
      pool: false
      headers: headers
    }, (err, validate_res, body) ->
      return next(err) if err?
      return authenticate(req, res, next) if validate_res.statusCode is 401
      
      try
        body = JSON.parse(body) if typeof body is 'string'
      catch e
        return next(e)
      req.keyless_user = body.user
      next()
  
  {
    protect: (req, res, next) ->
      req.query = betturl.parse(req.url).query
      req.resolved_protocol = req.get('x-forwarded-proto') ? req.protocol
      req.full_url = req.resolved_protocol + '://' + req.get('host') + req.url
      
      return next() if req.keyless_user?
      return validate_token(req, res, next, req.session.keyless_token) if req.session.keyless_token?
      return validate_ticket(req, res, next, req.query.ticket) if req.query.ticket?
      authenticate(req, res, next)
    
    logout: (req, res, next) ->
      delete req.keyless_user
      delete req.session.keyless_token
      url = opts.server + '/logout'
      url += '?callback=' + encodeURIComponent(url) if opts.on_logout?
      res.redirect(url)
  }
