chap = require '../lib/chap-server'

describe 'createNonce()', ->
    it 'should return a 40 character string', ->
        nonce = chap.createNonce('some-user-name')
        expect(typeof nonce).toBe 'string'
        expect(nonce.length).toBe 40

    it 'should never produce the same string', ->
        equal = false
        nonces = for i in [0..999]
            chap.createNonce('foo')

        count = 0
        for n in [0..999]
            nonce = nonces[n]
            for nplus in [0..999]
                if nplus is n then continue
                other = nonces[nplus]
                count += 1
                if other is nonce
                    equal = true
                    continue

        expect(count).toBe 999000
        expect(nonces.length).toBe 1000
        expect(equal).toBe false
