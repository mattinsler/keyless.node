betturl = require 'betturl'
request = require 'request'

# Opts are:
# - server
# - shared_key
# - on_logout

module.exports = (opts) ->
  throw new Error('') unless opts.server?
  
  {
    protect: (req, res, next) ->
      if req.session.keyless_user?
        req.keyless_user = req.session.keyless_user
        return next()
      
      url = (req.get('x-forwarded-protocol') ? req.protocol) + '://' + req.get('host') + req.url
      
      auth = -> res.redirect(opts.server + '/login?callback=' + encodeURIComponent(url))

      return auth() unless req.query.ticket?
      request {
        url: opts.server + '/validate?ticket=' + encodeURIComponent(req.query.ticket)
        pool: false
        headers: {
          'x-keyless-sso': opts.shared_key
        }
      }, (err, validate_res, body) ->
        return next(err) if err?
        body = JSON.parse(body) if typeof body is 'string'
        req.session.keyless_user = body.user
        parsed = betturl.parse(url)
        delete parsed.query.ticket
        url = betturl.format(parsed)
        res.redirect(url)
    
    logout: (req, res, next) ->
      delete req.session.keyless_user
      url = opts.server + '/logout'
      url += '?callback=' + encodeURIComponent(url) if opts.on_logout?
      res.redirect(url)
  }
