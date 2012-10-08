fs     = require 'fs'
{exec} = require 'child_process'

javascripts = {
  'webid' : [
    'VerificationAgent',
    'WebID'
  ]
}

task 'build', 'Build applications discribred in javascripts var', ->
  for javascript, sources of javascripts
    appContents = new Array
    console.log 'Processing ' + javascript
    for source, index in sources then do (source, index) ->
      console.log '  `- ' + source
      appContents[index] = fs.readFileSync "src/#{source}.coffee", 'utf8'
    fs.writeFile 'bin/' + javascript + '.coffee', appContents.join('\n\n'), 'utf8', (err) ->
      throw err if err
      console.log 'Compiling ' + javascript
      exec 'coffee --compile bin/' + javascript + '.coffee', (err, stdout, stderr) ->
        throw err if err
        console.log stdout + stderr
        fs.unlink 'bin/' + javascript + '.coffee', (err) ->
          throw err if err
          console.log 'Done.'