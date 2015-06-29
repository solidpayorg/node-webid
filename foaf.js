function Foaf(graph) {
  this.graph = graph
}
module.exports = Foaf

Foaf.prototype.parse = function() {
  return {
    title: "WebID Sucess !",
    name: this.getValue("name"),
    birthday: this.getValue("birthday"),
    webid: this.getWebid(),
    knows: this.getKnows()
  }
}

Foaf.prototype.getWebid = function() {
  var temp = this.graph.filter(function(t) {
    return t.predicate.equals("http://www.w3.org/ns/auth/cert#key")
  }).toArray()

  if (temp.length === 1) {
    return temp[0].subject.valueOf()
  }

  return ""
};

Foaf.prototype.getKnows = function() {
  var temp = this.graph.filter(function(t) {
    return t.predicate.equals("http://xmlns.com/foaf/0.1/knows");
  }).toArray();
  var result = [];

  temp.forEach(function(elem) {
    return result.push(elem.object.valueOf());
  })

  return result;
};

Foaf.prototype.getValue = function(value) {
  var temp = this.graph.filter(function(t) {
    return t.predicate.equals("http://xmlns.com/foaf/0.1/" + value);
  }).toArray();

  if (temp.length === 1) {
    return temp[0].object.valueOf();
  }

  return "";
}

