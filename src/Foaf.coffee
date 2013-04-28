_ = require('underscore');

class WebID.Foaf
  constructor: (graph) ->
    @graph = graph

  parse: ->
    title: "WebID Sucess !"
    name: @_getValue("name")
    birthday: @_getValue("birthday")
    webid: @_getWebid()
    knows: @_getKnows()

  ###
  Gets the WebID (URI).
  ###
  _getWebid: ->
    temp = @graph.filter((t) ->
    	t.predicate.equals "http://www.w3.org/ns/auth/cert#key"
    ).toArray()
    if temp.length is 1
    	temp[0].subject.valueOf()
    else
    	""

  ###
  Get knows relation
  @return List of "known" WebID.
  ###
  _getKnows: ->
    temp = @graph.filter((t) ->
      t.predicate.equals "http://xmlns.com/foaf/0.1/knows"
    ).toArray()
    result = []
    _.each temp, (elem) ->
      result.push elem.object.valueOf()
    result

  ###
  @param The FOAF value to get
  ###
  _getValue: (value) ->
    temp = @graph.filter((t) ->
      t.predicate.equals "http://xmlns.com/foaf/0.1/" + value
    ).toArray()
    if temp.length is 1
      temp[0].object.valueOf()
    #TODO: cover the case when 
    else
      ""