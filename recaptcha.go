// This package verifies reCaptcha v3 (http://www.google.com/recaptcha) responses
package recaptcha

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// google recaptcha response
type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// recaptcha api endpoint
const recaptchaServer = "https://www.google.com/recaptcha/api/siteverify"

// main object
type Recaptcha struct {
	PrivateKey string
}

// check : initiate a recaptcha verify request
func (r *Recaptcha) check(remoteAddr net.IP, captchaResponse string) (RecaptchaResponse, error) {
	// fire off request
	resp, err := http.PostForm(
		recaptchaServer,
		url.Values{
			"secret":   {r.PrivateKey},
			"remoteip": {remoteAddr.String()},
			"response": {captchaResponse},
		},
	)

	// request failed
	if err != nil {
		return RecaptchaResponse{Success: false}, err
	}

	// close response when function exits
	defer resp.Body.Close()

	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return RecaptchaResponse{Success: false}, err
	}

	// parse json to our response object
	var response RecaptchaResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return RecaptchaResponse{Success: false}, err
	}

	// return our object response
	return response, nil
}

// Verify : check user IP, captcha subject (= page) and captcha response
func (r *Recaptcha) Verify(remoteip net.IP, action string, response string, minScore uint) (success bool, err error) {
	resp, err := r.check(remoteip, response)
	// fetch/parsing failed
	if err != nil {
		return false, err
	}

	// captcha subject did not match
	if strings.ToLower(resp.Action) != strings.ToLower(action) {
		return false, errors.New("recaptcha actions do not match")
	}

	// recaptcha token was not valid
	if !resp.Success {
		return false, nil
	}

	// user treshold was not enough
	return uint(resp.Score) >= minScore, nil
}
