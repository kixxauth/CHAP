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

authenticate = (user, storeUser) ->
    user or= {}

    if not user or typeof user.username isnt 'string'
        throw new Error('A user.username string must be provided to .authenticate()')

    if not user.nonce or typeof user.nonce isnt 'string'
        user.nonce = null
    if not user.nextnonce or typeof user.nextnonce isnt 'string'
        user.nextnonce = null
    if not user.cnonce or typeof user.cnonce isnt 'string'
        user.cnonce = null
    if not user.response or typeof user.response isnt 'string'
        user.response = null
    if not user.passkey or typeof user.passkey isnt 'string'
        user.passkey = null

    # New user case (no nonce or nextnonce)
    if user.nonce is null or user.nextnonce is null
        user.nonce = createNonce(user.username)
        user.nextnonce = createNonce(user.username)
        user.message = exports.USER_NA
        user.authenticated = false
        user.passkey = null
        storeUser(user)
        return user

    # Missing cnonce or response credentials
    if user.cnonce is null or user.response is null
        user.message = exports.MISSING_CREDS
        user.authenticated = false
        return user

    # No stored passkey, so the user is setting or re-setting their account
    if user.passkey is null
        user.passkey = user.cnonce
        user.nonce = user.nextnonce
        user.nextnonce = createNonce(user.username)
        user.authenticated = true
        user.message = exports.SET_PASSKEY
        storeUser(user)
        return user

    # Now that we know the passkey, nonce, and nextnonce we have to make sure
    # that the client has actually computed the response and cnonce with the
    # nonce, nextnonce, and user secret.
    falseCnonce = sha1(sha1(user.nextnonce))
    falseResponse = sha1(user.nonce)
    if user.cnonce is falseCnonce or user.response is falseResponse
        user.authenticated = false
        user.message = exports.UNMODIFIED
        return user

    # Passkey mismatch; authentication denied
    if sha1(user.response) isnt user.passkey
        user.authenticated = false
        user.message = exports.DENIED
        return user

    user.passkey = user.cnonce
    user.nonce = user.nextnonce
    user.nextnonce = createNonce(user.username)
    user.authenticated = true
    user.message = exports.OK
    storeUser(user)
    return user

exports.authenticate = authenticate
