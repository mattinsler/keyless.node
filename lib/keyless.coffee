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
    # console.log 'KEYLESS-NODE: redirect_without_ticket'
    res.redirect(remove_ticket_from_url(req.keyless.client.full_url))
  
  authenticate = (req, res, next) ->
    # console.log 'KEYLESS-NODE: authenticate'
    delete req.keyless_user
    delete req.session.keyless_token
    res.redirect(opts.server + '/login?callback=' + encodeURIComponent(remove_ticket_from_url(req.keyless.client.full_url)))
  
  validate_ticket = (req, res, next, ticket) ->
    # console.log 'KEYLESS-NODE: validate_ticket'
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
      # console.log 'KEYLESS-NODE: validate_ticket: ' + validate_res.statusCode + ' - ' + require('util').inspect(body)
      status_class = parseInt(validate_res.statusCode / 100)
      return authenticate(req, res, next) unless status_class is 2
      
      try
        body = JSON.parse(body) if typeof body is 'string'
      catch e
        return next(e)
      req.session.keyless_token = body.token
      redirect_without_ticket(req, res, next)
  
  validate_token = (req, res, next, token) ->
    # console.log 'KEYLESS-NODE: validate_token'
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
      # console.log 'KEYLESS-NODE: validate_token: ' + validate_res.statusCode + ' - ' + require('util').inspect(body)
      status_class = parseInt(validate_res.statusCode / 100)
      return authenticate(req, res, next) unless status_class is 2
      
      try
        body = JSON.parse(body) if typeof body is 'string'
      catch e
        return next(e)
      req.keyless_user = body.user
      req.session.keyless_token = token
      return redirect_without_ticket(req, res, next) if req.keyless.client.query.auth_ticket?
      get_user(req, res, next)
  
  get_user = (req, res, next) ->
    # console.log 'KEYLESS-NODE: get_user'
    return next() unless req.keyless_user? and opts.get_user_from_keyless_user? and typeof opts.get_user_from_keyless_user is 'function'
    
    opts.get_user_from_keyless_user req.keyless_user, (err, user) ->
      return next(err) if err?
      req.user = user
      next()
  
  obj = {
    opts: opts
    
    middleware: ->
      (req, res, next) ->
        # console.log 'KEYLESS-NODE: middleware'
        req.keyless ?= {}
        req.keyless.client ?= {}
        req.keyless.client.query = betturl.parse(req.url).query
        req.keyless.client.resolved_protocol = req.get('x-forwarded-proto') ? req.protocol
        req.keyless.client.full_url = req.keyless.client.resolved_protocol + '://' + req.get('host') + req.url
        
        return get_user(req, res, next) if req.keyless_user?
        return validate_token(req, res, next, req.keyless.client.query.auth_token) if req.keyless.client.query.auth_token?
        return validate_token(req, res, next, req.session.keyless_token) if req.session.keyless_token?
        return validate_ticket(req, res, next, req.keyless.client.query.auth_ticket) if req.keyless.client.query.auth_ticket?
        next()
    
    protect: (req, res, next) ->
      # console.log 'KEYLESS-NODE: protect'
      return next(new Error('Be sure to use the keyless.middleware() in your middleware stack')) unless req.keyless?.client?
      
      return next() if req.keyless_user?
      authenticate(req, res, next)
    
    logout: (req, res, next) ->
      delete req.keyless_user
      delete req.session.keyless_token
      url = opts.server + '/logout'
      url += '?callback=' + encodeURIComponent(url) if opts.on_logout?
      res.redirect(url)
  }
  
  obj.__defineSetter__ 'get_user_from_keyless_user', (value) ->
    opts.get_user_from_keyless_user = value
  
  obj
