The CHAP

Challenge Handshake Authentication Protocol
-------------------------------------------

A simple challenge handshake implementation for JavaScript environments
including Node.js and browsers.

Based on the [alternative CHAP algorithm by Paul Johnston](http://pajhome.org.uk/crypt/md5/advancedauth.html#alternative)

[CHAP by Wikipedia](http://en.wikipedia.org/wiki/Challenge-Handshake_Authentication_Protocol)

This CHAP implementation is actually a strengthened variation of the typical
CHAP protocol. It only requires that the client machine (the user) actually
knows what the password is.

One of the best benefits of the CHAP protocol is that neither plain text nor
hashed password equivalents need to be stored by the servers. Extracting a
password from stolen authentication data becomes much more difficult for
attackers, and "man in the middle" dictionary attacks are nearly impossible.

> The Chap believes that a society without courteous behaviour and proper
> headwear is a society on the brink of moral and sartorial collapse, and it
> seeks to reinstate such outmoded but indispensable gestures as hat doffing,
> giving up one's seat to a lady and regularly using a trouser press.

How it works
------------

### When a new user account is created:

1. The client sends a user name string to the server.
2. If the user does not exist, it is created. Otherwise the server responds with an indication that the user already exists.
3. If the user was created a 'nonce' and 'nextnonce' attributes are added to the stored user object. Both of these attributes are random, non-guessable, strings.
4. The server sends back the user name, the nonce, and the nextnonce to the client.
5. The client hashes the nonce along with the user's password. We refer to this new string as the response.
6. The client hashes the nextnonce along with the user's password, and then hashes the result again. We refer to this new string as the cnonce.
7. The client sends the user name string, the response, and the cnonce back to the server.
8. The server assigns the nonce user attribute to the value of the nextnonce user attribute.
9. The server assigns the nextnonce user attribute to a newly created random string.
10. The server assigns the cnonce from the client to the passkey attribute of the user. 
11. The server stores the user, completing the user creation process.

In the following pseudo code example the hash() function is a sha1 hash.

    CLIENT -> [username="foo"] -> SERVER
    SERVER user = User() or abort()
    SERVER nonce = createNonce() and nextnonce = createNonce()
    SERVER -> [username="foo", nonce="sdfp0893w4r", nextnonce="sd09u234"] -> CLIENT
    CLIENT response = hash(nonce + passkey)
    CLIENT cnonce = hash(hash(nextnonce + passkey))
    CLIENT -> [username="foo", cnonce="lksdf09", response="asdf098w"] -> SERVER
    SERVER user.nonce = user.nextnonce
    SERVER user.nextnonce = createNonce()
    SERVER user.passkey = cnonce
    SERVER persists user data

### When authentication is requested for an existing user:

1. The client sends a username string.
2. The server responds with the last known nonce and nexnonce.
3. The client hashes the nonce along with the user's password. We refer to this new string as the response.
4. The client hashes the nextnonce along with the user's password two times. We refer to this new string as the cnonce.
5. The client sends the user name string, the response, and the cnonce back to the server.
6. The server then performs a hash on the response string. If the new hash matches the stored passkey for the user, the user is authenticated. If not, the user is denied.
7. If the user was authenticated, the server assigns the nonce user attribute to the value of the nextnonce user attribute.
8. If the user was authenticated, the server assigns the nextnonce user attribute to a newly created random string.
9. If the user was authenticated, the server assigns the cnonce from the client to the passkey attribute of the user. 
10. The server stores the user, completing the user authentication process.

In the following pseudo code example the hash() function is a sha1 hash.

    CLIENT -> [username="foo_man_choo"] -> SERVER
    SERVER nonce = createNonce() and nextnonce = createNonce()
    SERVER -> [username="foo_man_choo", nonce="sdfp0893w4r", nextnonce="sd09u234"] -> CLIENT
    CLIENT response = hash(nonce + passkey)
    CLIENT cnonce = hash(hash(nextnonce + passkey))
    CLIENT -> [username="foo_man_choo", cnonce="lksdf09", response="asdf098w"] -> SERVER
    SERVER if hash(response) != user.passkey abort()
    SERVER user.nonce = user.nextnonce
    SERVER user.nextnonce = createNonce()
    SERVER user.passkey = cnonce
    SERVER persists user data

Development Notes
-----------------

### .gitignore
! Note that JS files (`*.js`) are *not* tracked, since all JS source code is
written in CoffeeScript (`*.coffee`).

Copyright and License
---------------------
copyright: (c) 2011 by Kris Walker (kris@kixx.name).

Unless otherwise indicated, all source code is licensed under the MIT license.
See MIT-LICENSE for details.
