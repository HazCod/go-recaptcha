// example.go
//
// A simple HTTP server which presents a reCaptcha input form and evaulates the result,
// using the github.com/dpapathanasiou/go-recaptcha package.
//
// See the main() function for usage.
package main

import (
	"fmt"
	"github.com/hazcod/go-recaptcha"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

var (
	myRecaptchaPublicKey string
	myRecaptcha          recaptcha.Recaptcha
)

const (
	pageTop = `<!DOCTYPE HTML><html><head>
<style>.error{color:#ff0000;} .ack{color:#0000ff;}</style><title>Recaptcha Test</title></head>
<body><div style="width:100%"><div style="width: 50%;margin: 0 auto;">
<h3>Recaptcha Test</h3>
<p>This is a test form for the go-recaptcha package</p>`
	form = `<form action="/" method="POST">
	    <script src="https://www.google.com/recaptcha/api.js"></script>
			<div class="g-recaptcha" data-sitekey="%s"></div>
    	<input type="submit" name="button" value="Ok">
</form>`
	pageBottom = `</div></div></body></html>`
	anError    = `<p class="error">%s</p>`
	anAck      = `<p class="ack">%s</p>`
)

// processRequest accepts the http.Request object, finds the reCaptcha form variables which
// were input and sent by HTTP POST to the server, then calls the recaptcha package's Confirm()
// method, which returns a boolean indicating whether or not the client answered the form correctly.
func processRequest(request *http.Request) (result bool) {
	recaptchaResponse, responseFound := request.Form["g-recaptcha-response"]
	if !responseFound {
		return false
	}

	ip, _, err := net.ParseCIDR("127.0.0.1")
	if err != nil {
		log.Printf("could not parse ip: %v", err)
	}

	result, score, err := myRecaptcha.Check(ip, "my-login-page", recaptchaResponse[0])
	if err != nil {
		log.Printf("recaptcha error: %v", err)
	}

	log.Printf("User score was: %d", score)

	return result
}

// homePage is a simple HTTP handler which produces a basic HTML page
func homePage(writer http.ResponseWriter, request *http.Request) {
	err := request.ParseForm()
	fmt.Fprint(writer, pageTop)

	if err != nil {
		fmt.Fprintf(writer, fmt.Sprintf(anError, err))
		return
	}

	_, buttonClicked := request.Form["button"]
	if buttonClicked {
		if processRequest(request) {
			fmt.Fprint(writer, fmt.Sprintf(anAck, "Recaptcha was correct!"))
		} else {
			fmt.Fprintf(writer, fmt.Sprintf(anError, "Recaptcha was incorrect; try again."))
		}
	}

	fmt.Fprint(writer, fmt.Sprintf(form, myRecaptchaPublicKey))
	fmt.Fprint(writer, pageBottom)
}

// main expects two command-line arguments: the reCaptcha public key for producing the HTML form and the reCaptcha private key
func main() {
	if len(os.Args) != 3 {
		fmt.Printf("usage: %s <reCaptcha public key> <reCaptcha private key>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	myRecaptchaPublicKey = os.Args[1]
	myRecaptcha = recaptcha.Recaptcha{PrivateKey: os.Args[2]}

	http.HandleFunc("/", homePage)
	if err := http.ListenAndServe(":9001", nil); err != nil {
		log.Fatal("failed to start server", err)
	}
}
