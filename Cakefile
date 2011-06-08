fs        = require 'fs'
path      = require 'path'
childProc = require 'child_process'

verbose = true
colored = true

extendGlobalWith = (obj) ->
    for key, val of obj
        global[key] = val

checkAndRemoveFile = (filepath) ->
    if path.existsSync(filepath)
        return fs.unlinkSync(filepath)

task 'test', 'run the full spec test suite', ->
    try
        jasmine = require './dev/third_party/jasmine-node/lib/jasmine-node'
    catch requireError
        console.log 'missing a development testing dependency:'
        process.stderr.write "#{ JSON.stringify requireError }\n"
        process.exit 1

    extendGlobalWith jasmine

    specPath = path.join(__dirname, 'spec')

    afterSpecRun = (runner, log) ->
        failures = runner.results().failedCount
        if failures then process.exit 1 else process.exit 0

    pattern = new RegExp "spec\.coffee$", "i"
    jasmine.executeSpecsInFolder(specPath, afterSpecRun, verbose, colored, pattern)
