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
  
  remove_ticket_from_url = (url) ->
    parsed = betturl.parse(url)
    delete parsed.query.auth_ticket
    betturl.format(parsed)
  
  redirect_without_ticket = (req, res, next) ->
    res.redirect(remove_ticket_from_url(req.full_url))
  
  authenticate = (req, res, next) ->
    delete req.keyless_user
    delete req.session.keyless_token
    res.redirect(opts.server + '/login?callback=' + encodeURIComponent(remove_ticket_from_url(req.full_url)))
  
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
      status_class = parseInt(validate_res.statusCode / 100)
      return authenticate(req, res, next) unless status_class is 2
      
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
      status_class = parseInt(validate_res.statusCode / 100)
      return authenticate(req, res, next) unless status_class is 2
      
      try
        body = JSON.parse(body) if typeof body is 'string'
      catch e
        return next(e)
      req.keyless_user = body.user
      req.session.keyless_token = token
      return redirect_without_ticket(req, res, next) if req.query.auth_ticket?
      next()
  
  {
    protect: (req, res, next) ->
      req.query = betturl.parse(req.url).query
      req.resolved_protocol = req.get('x-forwarded-proto') ? req.protocol
      req.full_url = req.resolved_protocol + '://' + req.get('host') + req.url
      
      return next() if req.keyless_user?
      return validate_token(req, res, next, req.query.auth_token) if req.query.auth_token?
      return validate_token(req, res, next, req.session.keyless_token) if req.session.keyless_token?
      return validate_ticket(req, res, next, req.query.auth_ticket) if req.query.auth_ticket?
      authenticate(req, res, next)
    
    logout: (req, res, next) ->
      delete req.keyless_user
      delete req.session.keyless_token
      url = opts.server + '/logout'
      url += '?callback=' + encodeURIComponent(url) if opts.on_logout?
      res.redirect(url)
  }
