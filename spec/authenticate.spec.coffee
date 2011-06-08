crypto = require 'crypto'

chap = require '../lib/chap-server'

describe 'authenticate() invalid parameters', ->

    it 'should throw an error if the username string is not available', ->
        err = false
        try
            chap.authenticate()
        catch e
            err = e

        expect(typeof err).toBe 'object'
        expect(err.message).toBe 'A user.username string must be provided to .authenticate()'
        return

describe 'create a new user with authenticate()', ->

    it 'should "create" a new user', ->
        user =
            username: 'x'

        testPersistCalled = false

        checkUserAttr = (user) ->
            # nonce
            expect(typeof user.nonce).toBe 'string'
            expect(user.nonce.length).toBe 40

            # nextnonce
            expect(typeof user.nextnonce).toBe 'string'
            expect(user.nextnonce.length).toBe 40

            # passkey
            expect(user.passkey).toBe null

            # authenticated
            expect(user.authenticated).toBe false

            # message
            expect(user.message).toBe chap.USER_NA
            return

        testPersist = (user) ->
            testPersistCalled = true
            return checkUserAttr(user)

        newUser = chap.authenticate(user, testPersist)
        checkUserAttr(newUser)

        expect(testPersistCalled).toBe true
        return


describe 'authenticate() should deny authentication without creds', ->

    it 'should deny authentication', ->
        user =
            username: 'x'
            nonce: 'y'
            nextnonce: 'z'

        testPersistCalled = false

        checkUserAttr = (user) ->
            # nonce
            expect(user.nonce).toBe 'y'

            # nextnonce
            expect(user.nextnonce).toBe 'z'

            # passkey
            expect(user.passkey).toBe null

            # authenticated
            expect(user.authenticated).toBe false

            # message
            expect(user.message).toBe chap.MISSING_CREDS
            return

        testPersist = (user) ->
            return testPersistCalled = true

        newUser = chap.authenticate(user, testPersist)
        checkUserAttr(newUser)

        expect(testPersistCalled).toBe false
        return


describe 'autheticate() should create a new passkey for a user without one', ->

    it 'should create a passkey and authenticate', ->
        user =
            username: 'x'
            nonce: 'a'
            nextnonce: 'b'
            cnonce: 'c'
            response: 'd'

        testPersistCalled = false

        checkUserAttr = (user) ->
            # nonce
            expect(user.nonce).toBe 'b'

            # nextnonce
            expect(typeof user.nextnonce).toBe 'string'
            expect(user.nextnonce.length).toBe 40

            # passkey
            expect(user.passkey).toBe 'c'

            # authenticated
            expect(user.authenticated).toBe true

            # message
            expect(user.message).toBe chap.SET_PASSKEY
            return

        testPersist = (user) ->
            testPersistCalled = true
            return checkUserAttr(user)

        newUser = chap.authenticate(user, testPersist)
        checkUserAttr(newUser)

        expect(testPersistCalled).toBe true
        return


describe 'authenticate() authentication', ->

    it 'should not authenticate if the passkey was not modified', ->
        nonce = 'a'
        nextnonce = 'b'
        response = chap.sha1(nonce)
        cnonce = chap.sha1(chap.sha1(nextnonce))

        user =
            username: 'x'
            nonce: nonce
            nextnonce: nextnonce
            cnonce: cnonce
            response: response
            passkey: 'y'

        testPersistCalled = false

        checkUserAttr = (user) ->
            # nonce
            expect(user.nonce).toBe 'a'

            # nextnonce
            expect(user.nextnonce).toBe 'b'

            # passkey
            expect(user.passkey).toBe 'y'

            # authenticated
            expect(user.authenticated).toBe false

            # message
            expect(user.message).toBe chap.UNMODIFIED
            return

        testPersist = (user) ->
            return testPersistCalled = true

        newUser = chap.authenticate(user, testPersist)
        checkUserAttr(newUser)

        expect(testPersistCalled).toBe false
        return

    it 'should not authenticate if the computed passkey does not match', ->
        user =
            username: 'x'
            nonce: 'x'
            nextnonce: 'x'
            cnonce: 'x'
            response: 'x'
            passkey: 'x'

        testPersistCalled = false

        checkUserAttr = (user) ->
            # nonce
            expect(user.nonce).toBe 'x'

            # nextnonce
            expect(user.nextnonce).toBe 'x'

            # passkey
            expect(user.passkey).toBe 'x'

            # authenticated
            expect(user.authenticated).toBe false

            # message
            expect(user.message).toBe chap.DENIED
            return

        testPersist = (user) ->
            return testPersistCalled = true

        newUser = chap.authenticate(user, testPersist)
        checkUserAttr(newUser)

        expect(testPersistCalled).toBe false
        return

    it 'should authenticate if the computed passkey matches', ->
        user =
            username: 'a'
            nonce: 'b'
            nextnonce: 'c'
            cnonce: 'd'
            response: 'e'
            passkey: '58e6b3a414a1e090dfc6029add0f3555ccba127f'

        testPersistCalled = false

        checkUserAttr = (user) ->
            # nonce
            expect(user.nonce).toBe 'c'

            # nextnonce
            expect(typeof user.nextnonce).toBe 'string'
            expect(user.nextnonce.length).toBe 40

            # passkey
            expect(user.passkey).toBe 'd'

            # authenticated
            expect(user.authenticated).toBe true

            # message
            expect(user.message).toBe chap.OK
            return

        testPersist = (user) ->
            testPersistCalled = true
            return checkUserAttr(user)

        newUser = chap.authenticate(user, testPersist)
        checkUserAttr(newUser)

        expect(testPersistCalled).toBe true
        return
