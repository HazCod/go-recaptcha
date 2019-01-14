go-recaptcha
============

About
-----

This package handles [reCaptcha](https://www.google.com/recaptcha) ([API version 3.0](https://developers.google.com/recaptcha/intro)) form submissions in [Go](http://golang.org/).

Usage
-----

Install the package in your environment:

```
go get github.com/hazcod/go-recaptcha
```

To use it within your own code, import <tt>github.com/hazcod/go-recaptcha</tt> and call:

```
recaptcha := Recaptcha{ PrivateKey: "your-recaptcha-private-key" }
```

Now call `recaptcha.Verify(remoteip net.IP, action string, response string, minScore uint)` which will return `(success bool, err error)`.


Usage Example
-------------

Included with this repo is [example.go](example/example.go), a simple HTTP server which creates the reCaptcha form and tests the input.

See the [instructions](example/README.md) for running the example for more details.

