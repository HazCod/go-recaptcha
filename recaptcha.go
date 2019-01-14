// Package recaptcha handles reCaptcha (http://www.google.com/recaptcha) form submissions
//
// This package is designed to be called from within an HTTP server or web framework
// which offers reCaptcha form inputs and requires them to be evaluated for correctness
//

package recaptcha

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

const recaptchaServer = "https://www.google.com/recaptcha/api/siteverify"

type Recaptcha struct {
	PrivateKey string
}

// check uses the client ip address, the challenge code from the reCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the reCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func (r *Recaptcha) check(remoteAddr net.IP, captchaResponse string) (RecaptchaResponse, error) {
	resp, err := http.PostForm(
		recaptchaServer,
		url.Values{
			"secret":   {r.PrivateKey},
			"remoteip": {remoteAddr.String()},
			"response": {captchaResponse},
		},
	)

	if err != nil {
		return RecaptchaResponse{Success: false}, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return RecaptchaResponse{Success: false}, err
	}

	var response RecaptchaResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return RecaptchaResponse{Success: false}, err
	}

	return response, nil
}

// Confirm is the public interface function.
// It calls check, which the client ip address, the challenge code from the reCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the reCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func (r *Recaptcha) Confirm(remoteip net.IP, response string) (result bool, err error) {
	resp, err := r.check(remoteip, response)
	result = resp.Success
	return
}
