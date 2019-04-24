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
type recaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       uint      `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// recaptcha api endpoint
const (
	requestTimeout  = time.Second * 10
	recaptchaServer = "https://www.google.com/recaptcha/api/siteverify"
)

// main object
type Recaptcha struct {
	PrivateKey string
}

// check : initiate a recaptcha verify request
func (r *Recaptcha) requestVerify(remoteAddr net.IP, captchaResponse string) (recaptchaResponse, error) {
	// fire off request with a timeout of 10 seconds
	httpClient := http.Client{Timeout: requestTimeout}
	resp, err := httpClient.PostForm(
		recaptchaServer,
		url.Values{
			"secret":   {r.PrivateKey},
			"remoteip": {remoteAddr.String()},
			"response": {captchaResponse},
		},
	)

	// request failed
	if err != nil {
		return recaptchaResponse{Success: false}, err
	}

	// close response when function exits
	defer resp.Body.Close()

	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return recaptchaResponse{Success: false}, err
	}

	// parse json to our response object
	var response recaptchaResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return recaptchaResponse{Success: false}, err
	}

	// return our object response
	return response, nil
}

// Check : check user IP, captcha subject (= page) and captcha response but return treshold
func (r *Recaptcha) Check(remoteip net.IP, action string, response string) (success bool, score uint, err error) {
	resp, err := r.requestVerify(remoteip, response)
	// fetch/parsing failed
	if err != nil {
		return false, 0, err
	}

	// captcha subject did not match
	if strings.ToLower(resp.Action) != strings.ToLower(action) {
		return false, 0, errors.New("recaptcha actions do not match")
	}

	// recaptcha token was not valid
	if !resp.Success {
		return false, 0, nil
	}

	// user treshold was not enough
	return true, resp.Score, nil
}

// Verify : check user IP, captcha subject (= page) and captcha response
func (r *Recaptcha) Verify(remoteip net.IP, action string, response string, minScore uint) (success bool, err error) {
	success, score, err := r.Check(remoteip, action, response)

	// return false if response failed
	if !success || err != nil {
		return false, err
	}

	// user score was not enough
	return score >= minScore, nil
}
