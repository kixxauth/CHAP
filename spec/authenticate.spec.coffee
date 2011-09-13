crypto = require 'crypto'

chap = require '../lib/chap-server'

describe 'Authenticator.validate() invalid parameters', ->

    it 'should throw an error if the username string is not available', ->
        err = false
        auth = chap.createAuth().updateUser()

        try
            auth.validate()
        catch e
            err = e

        expect(typeof err).toBe 'object'
        expect(err.message).toBe 'A user.username string must be provided to authenticate'
        return

describe 'create a new user with authenticate()', ->

    it 'should "create" a new user', ->
        testPersistCalled = false

        auth = chap.createAuth({username: 'x'})
            .updateUser()
            .validate()

        nonce = null
        nextnonce = null

        testPersist = (user) ->
            testPersistCalled = true
            expect(user.username).toBe 'x'
            expect(typeof user.nonce).toBe 'string'
            expect(user.nonce.length).toBe 40
            nonce = user.nonce
            expect(typeof user.nextnonce).toBe 'string'
            expect(user.nextnonce.length).toBe 40
            nextnonce = user.nextnonce
            expect(user.passkey).toBe null
            return

        newUser = auth.authenticate(testPersist)
        expect(typeof newUser.passkey).toBe 'undefined'
        expect(newUser.nonce).toBe nonce
        expect(newUser.nextnonce).toBe nextnonce
        expect(newUser.authenticated).toBe false
        expect(newUser.message).toBe chap.USER_NA
        expect(newUser.username).toBe 'x'

        expect(testPersistCalled).toBe true
        return


describe 'authenticate() should deny authentication without creds', ->

    it 'should deny authentication', ->
        testPersistCalled = false

        auth = chap.createAuth({username: 'x'})
            .updateUser({nonce: 'y', nextnonce: 'z'})
            .validate()

        testPersist = (user) ->
            return testPersistCalled = true

        newUser = auth.authenticate(testPersist)
        expect(typeof newUser.passkey).toBe 'undefined'
        expect(newUser.nonce).toBe 'y'
        expect(newUser.nextnonce).toBe 'z'
        expect(newUser.authenticated).toBe false
        expect(newUser.message).toBe chap.MISSING_CREDS
        expect(newUser.username).toBe 'x'
        return

        expect(testPersistCalled).toBe false
        return


describe 'autheticate() should create a new passkey for a user without one', ->

    it 'should create a passkey and authenticate', ->
        testPersistCalled = false

        auth = chap.createAuth({username: 'x', cnonce: 'c', response: 'd'})
            .updateUser({nonce: 'a', nextnonce: 'b'})
            .validate()


        nextnonce = null

        testPersist = (user) ->
            testPersistCalled = true
            expect(user.username).toBe 'x'
            expect(user.nonce).toBe 'b'
            expect(typeof user.nextnonce).toBe 'string'
            expect(user.nextnonce.length).toBe 40
            nextnonce = user.nextnonce
            expect(user.passkey).toBe 'c'
            expect(typeof user.authenticated).toBe 'undefined'
            return

        newUser = auth.authenticate(testPersist)
        expect(typeof newUser.passkey).toBe 'undefined'
        expect(newUser.nonce).toBe 'b'
        expect(newUser.nextnonce).toBe nextnonce
        expect(newUser.authenticated).toBe true
        expect(newUser.message).toBe chap.SET_PASSKEY
        expect(testPersistCalled).toBe true
        expect(newUser.username).toBe 'x'
        return


describe 'authenticate() authentication', ->

    it 'should not authenticate if the passkey was not modified', ->
        nonce = 'a'
        nextnonce = 'b'
        response = chap.sha1(nonce)
        cnonce = chap.sha1(chap.sha1(nextnonce))

        user =
            username: 'x'
            cnonce: cnonce
            response: response

        testPersistCalled = false

        auth = chap.createAuth(user)
            .updateUser({nonce: nonce, nextnonce: nextnonce, passkey: 'y'})
            .validate()

        testPersist = (user) ->
            return testPersistCalled = true

        newUser = auth.authenticate(testPersist)
        expect(typeof newUser.passkey).toBe 'undefined'
        expect(newUser.nonce).toBe 'a'
        expect(newUser.nextnonce).toBe 'b'
        expect(newUser.authenticated).toBe false
        expect(newUser.message).toBe chap.UNMODIFIED
        expect(newUser.username).toBe 'x'

        expect(testPersistCalled).toBe false
        return

    it 'should not authenticate if the computed passkey does not match', ->
        user =
            username: 'x'
            cnonce: 'x'
            response: 'x'

        testPersistCalled = false

        auth = chap.createAuth(user)
            .updateUser({nonce: 'x', nextnonce: 'x', passkey: 'x'})
            .validate()

        testPersist = (user) ->
            return testPersistCalled = true

        newUser = auth.authenticate(testPersist)
        expect(typeof newUser.passkey).toBe 'undefined'
        expect(newUser.nonce).toBe 'x'
        expect(newUser.nextnonce).toBe 'x'
        expect(newUser.authenticated).toBe false
        expect(newUser.message).toBe chap.DENIED
        expect(newUser.username).toBe 'x'

        expect(testPersistCalled).toBe false
        return

    it 'should authenticate if the computed passkey matches', ->
        user =
            username: 'a'
            cnonce: 'd'
            response: 'e'

        storedUser =
            passkey: '58e6b3a414a1e090dfc6029add0f3555ccba127f'
            nonce: 'b'
            nextnonce: 'c'

        testPersistCalled = false

        auth = chap.createAuth(user)
            .updateUser(storedUser)
            .validate()

        testPersist = (user) ->
            testPersistCalled = true
            expect(user.username).toBe 'a'
            expect(user.nonce).toBe 'c'
            expect(typeof user.nextnonce).toBe 'string'
            expect(user.nextnonce.length).toBe 40
            expect(user.passkey).toBe 'd'
            return

        newUser = auth.authenticate(testPersist)
        expect(newUser.username).toBe 'a'
        expect(typeof newUser.passkey).toBe 'undefined'
        expect(newUser.authenticated).toBe true
        expect(newUser.message).toBe chap.OK
        expect(newUser.nonce).toBe 'c'
        expect(typeof newUser.nextnonce).toBe 'string'
        expect(newUser.nextnonce.length).toBe 40

        expect(testPersistCalled).toBe true
        return
