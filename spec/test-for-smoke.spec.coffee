describe 'testing for smoke...', ->
    it 'should not be smoking', ->
        makeTimer = ->
            done = false
            whenTimeout = -> done = true
            setTimeout whenTimeout, 500

            return ->
                return done

        timer = makeTimer()
        expect(timer()).toBe false
        waitsFor timer, 'smoke timer', 600

        runs -> expect(timer()).toBe true
