crypto = require 'crypto'

exports.USER_NA = 'user does not exist'
exports.MISSING_CREDS = 'proper cnonce or response was not supplied'
exports.SET_PASSKEY = 'setting or resetting the user passkey'
exports.UNMODIFED = 'the cnonce or response were not modified by the client'
exports.DENIED = 'the supplied passkey response did not authenticate'
exports.OK = 'authenticated'

CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz'

sha1 = (str) ->
    hash = crypto.createHash('sha1')
    hash.update(str)
    return hash.digest('hex')

exports.sha1 = sha1

createNonce = (keyString) ->
    rstring = ''
    charsLength = CHARS.length
    for iter in [1..40]
        rnum = Math.floor(Math.random() * charsLength)
        rstring += CHARS.charAt(rnum)

    rstring += (new Date()).toString()

    hmac = crypto.createHmac('sha1', keyString)
    hmac.update(rstring)
    return hmac.digest('hex')

exports.createNonce = createNonce

createAuth = (user) ->
    username  = null
    nonce     = null
    nextnonce = null
    cnonce    = null
    response  = null
    passkey   = null

    user or= {}
    if user.username and typeof user.username is 'string'
        username = user.username
    if user.response and typeof user.response is 'string'
        response = user.response
    if user.cnonce and typeof user.cnonce is 'string'
        cnonce = user.cnonce

    self =
        updateUser: (storedUser) ->
            storedUser or= {}
            if storedUser.nonce and typeof storedUser.nonce is 'string'
                nonce = storedUser.nonce
            if storedUser.nextnonce and typeof storedUser.nextnonce is 'string'
                nextnonce = storedUser.nextnonce
            if storedUser.passkey and typeof storedUser.passkey is 'string'
                passkey = storedUser.passkey
            return

        validate: ->
            if not username
                msg = 'A user.username string must be provided to authenticate'
                throw new Error(msg)
            return

        authenticate: (storeUser) ->
            storedUser = {}
            returnedUser = {}

            returnedUser.username = storedUser.username = username
            returnedUser.nonce = storedUser.nonce = nonce
            returnedUser.nextnonce = storedUser.nextnonce = nextnonce
            storedUser.passkey = passkey

            # New user case (no nonce or nextnonce)
            if nonce is null or nextnonce is null
                returnedUser.nonce = storedUser.nonce = createNonce(username)
                returnedUser.nextnonce = storedUser.nextnonce = createNonce(username)
                returnedUser.message = exports.USER_NA
                returnedUser.authenticated = false
                storedUser.passkey = null
                storeUser(storedUser)
                return returnedUser

            # Missing cnonce or response credentials
            if cnonce is null or response is null
                returnedUser.message = exports.MISSING_CREDS
                returnedUser.authenticated = false
                return returnedUser

            # No stored passkey, so the user is setting or re-setting their account
            if passkey is null
                storedUser.passkey = cnonce
                returnedUser.nonce = storedUser.nonce = nextnonce
                returnedUser.nextnonce = storedUser.nextnonce = createNonce(username)
                returnedUser.authenticated = true
                returnedUser.message = exports.SET_PASSKEY
                storeUser(storedUser)
                return returnedUser

            # Now that we know the passkey, nonce, and nextnonce we have to make sure
            # that the client has actually computed the response and cnonce with the
            # nonce, nextnonce, and user secret.
            falseCnonce = sha1(sha1(nextnonce))
            falseResponse = sha1(nonce)
            if cnonce is falseCnonce or response is falseResponse
                returnedUser.authenticated = false
                returnedUser.message = exports.UNMODIFIED
                return returnedUser

            # Passkey mismatch; authentication denied
            if sha1(response) isnt passkey
                returnedUser.authenticated = false
                returnedUser.message = exports.DENIED
                return returnedUser

            # User is OK
            storedUser.passkey = cnonce
            returnedUser.nonce = storedUser.nonce = nextnonce
            returnedUser.nextnonce = storedUser.nextnonce = createNonce(username)
            returnedUser.authenticated = true
            returnedUser.message = exports.OK
            storeUser(storedUser)
            return returnedUser

    return self

exports.createAuth = createAuth
