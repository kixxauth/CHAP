crypto = require 'crypto'

CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz'

createNonce = (keyString) ->
    rstring = ''
    charsLength = CHARS.length
    for iter in [1..40]
        rnum = Math.floor(Math.random() * charsLength)
        rstring += CHARS.charAt(rnum)

    rstring += (new Date()).toString()

    hmac = crypto.createHmac('sha1', keyString)
    hash = crypto.createHash('sha1')
    hmac.update(rstring)
    hash.update(hmac.digest('hex'))
    return hash.digest('hex')

exports.createNonce = createNonce
