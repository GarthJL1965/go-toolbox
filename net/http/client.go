package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	neturl "net/url"

	"go.imperva.dev/toolbox/crypto"
	"go.imperva.dev/zerolog/log"
)

// Client represents an HTTP client.
type Client struct {
	// ClientCertificates is a list of certificates to pass for client authentication.
	ClientCertificates []tls.Certificate

	// DisableSSLVerification disables HTTPS certificate verification when connecting to a server. You should
	// only do this if you are *really* sure. Otherwise, add the server's certificate to the RootCertificates
	// pool.
	DisableSSLVerification bool

	// RootCertificates is a pool of root CA certificates to trust.
	RootCertificates *crypto.CertificatePool

	// unexported variables
	proxyConfig ProxyConfig // full proxy configuration settings
	getProxy    proxyFunc   // function to determine if URL requires proxying
}

// NewClient returns a new HTTP client object.
func NewClient(proxyConfig ProxyConfig) *Client {
	return &Client{
		ClientCertificates:     []tls.Certificate{},
		DisableSSLVerification: false,
		RootCertificates:       nil,
		proxyConfig:            proxyConfig,
		getProxy:               proxyConfig.ProxyFunc(),
	}
}

// Delete performs a DELETE request for the given URL and returns the raw body byte array.
func (c *Client) Delete(url string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	return c.doRequest("DELETE", url, headers, body)
}

// Get performs a GET request for the given URL and returns the raw body byte array.
func (c *Client) Get(url string, headers map[string]string) (*http.Response, []byte, error) {
	return c.doRequest("GET", url, headers, nil)
}

// Options performs an OPTIONS request for the given URL and returns the raw body byte array.
func (c *Client) Options(url string, headers map[string]string) (*http.Response, []byte, error) {
	return c.doRequest("OPTIONS", url, headers, nil)
}

// Patch performs a PATCH request for the given URL and returns the raw body byte array.
func (c *Client) Patch(url string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	return c.doRequest("PATCH", url, headers, body)
}

// Post performs a POST request for the given URL and returns the raw body byte array.
func (c *Client) Post(url string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	return c.doRequest("POST", url, headers, body)
}

// Put performs a PUT request for the given URL and returns the raw body byte array.
func (c *Client) Put(url string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	return c.doRequest("PUT", url, headers, body)
}

// NewRequest creates a new HTTP request object using any configured proxy information.
//
// Note that only HTTP Basic authentication is supported for proxied requests.
func (c *Client) NewRequest(method, url string, body io.Reader) (*http.Client, *http.Request, error) {
	restoreLogger, _ := log.ReplaceGlobal(
		log.With().PackageCaller().Str("method", method).Str("url", url).Logger())
	defer restoreLogger()

	// parse the URL passed in
	parsedUrl, err := neturl.Parse(url)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to parse URL '%s': %s", url, err.Error())
		return nil, nil, err
	}

	// get any proxy URL required by our HTTP configuration
	proxyURL, err := c.getProxy(parsedUrl)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to check proxy status for URL '%s': %s", url, err.Error())
		return nil, nil, err
	}

	// add proxy authorization if required
	basicAuth := ""
	if proxyURL != nil {
		if proxyURL.Scheme == "http" &&
			(c.proxyConfig.HTTPProxyUser != "" || c.proxyConfig.HTTPProxyPass != "") {
			auth := fmt.Sprintf("%s:%s", c.proxyConfig.HTTPProxyUser, c.proxyConfig.HTTPProxyPass)
			basicAuth = fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(auth)))
		} else if proxyURL.Scheme == "https" &&
			(c.proxyConfig.HTTPSProxyUser != "" || c.proxyConfig.HTTPSProxyPass != "") {
			auth := fmt.Sprintf("%s:%s", c.proxyConfig.HTTPSProxyUser, c.proxyConfig.HTTPSProxyPass)
			basicAuth = fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(auth)))
		}
	}

	// configure HTTP transport object
	var rootCAs *x509.CertPool
	if c.RootCertificates != nil {
		rootCAs = c.RootCertificates.CertPool
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       c.ClientCertificates,
			RootCAs:            rootCAs,
			InsecureSkipVerify: c.DisableSSLVerification,
		},
		ProxyConnectHeader: http.Header{},
	}
	if proxyURL != nil {
		log.Debug().Msgf("using proxy URL: %s", proxyURL.String())
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	if basicAuth != "" {
		transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuth)
		log.Debug().Msg("added Proxy-Authorization header for CONNECT")
	}
	transport.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))

	// create a new HTTP client
	client := &http.Client{
		Transport: transport,
	}

	// create the request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to create '%s' request for URL '%s': %s", method, url, err.Error())
		return nil, nil, err
	}
	if basicAuth != "" {
		req.Header.Add("Proxy-Authorization", basicAuth)
		log.Debug().Msg("added Proxy-Authorization header to request")
	}
	return client, req, nil
}

// doRequest handles performing the HTTP request and parsing the response.
func (c *Client) doRequest(method string, url string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	restoreLogger, _ := log.ReplaceGlobal(
		log.With().PackageCaller().Str("method", method).Str("url", url).Logger())
	defer restoreLogger()

	// create the request
	if body == nil {
		body = []byte{}
	}
	client, req, err := c.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to create %s request: %s", method, err.Error())
		return nil, nil, err
	}

	// add headers to request
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// perform the request
	log.Debug().Msgf("HTTP Request: %+v", req)
	resp, err := client.Do(req)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to perform %s request to '%s': %s", method, url, err.Error())
		return nil, nil, err
	}
	log.Debug().Msgf("HTTP Response: %+v", resp)
	return c.parseResponse(resp)
}

// parseResponse parses the response from the HTTP request and returns the raw byte body.
func (c *Client) parseResponse(resp *http.Response) (*http.Response, []byte, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	log.Debug().Msgf("HTTP Response: %+v", resp)
	if body != nil {
		log.Debug().Msgf("HTTP Response Body: %s", string(body))
	}
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to read response body: %s", err.Error())
		return resp, nil, err
	}
	if resp.StatusCode >= 400 {
		err := fmt.Errorf("HTTP request returned error code %d", resp.StatusCode)
		log.
			Error().Stack().
			Err(err).
			Msg(err.Error())
		return resp, body, err
	}
	return resp, body, nil
}