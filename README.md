# node-webid

[![Build Status](https://travis-ci.org/linkeddata/node-webid.svg?branch=master)](https://travis-ci.org/linkeddata/node-webid)
[![NPM Version](https://img.shields.io/npm/v/webid.svg?style=flat)](https://npm.im/webid)
[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat%20%E2%86%92-brightgreen.svg?style=flat)](http://gitter.im/linkeddata/node-webid)


Node.js module with tools to help using [WebID](http://linkeddata.github.io/SoLiD/#identity-management-based-on-webid).

## Installation

```
$ npm install webid --save
```

## Features

- [x] Retrieve a WebID
- [x] Verify a WebID+TLS
- [ ] Generate a WebID+TLS


## Usage

```javascript
var webid = require('webid');
webid.verify(certificate, function (err, result) {
  if (err) {
    //An error occurred
  }
  //Success! User is identified
});
```

## History

Originally forked from [magnetik/node-webid](https://github.com/magnetik/node-webid)

## License

MIT
