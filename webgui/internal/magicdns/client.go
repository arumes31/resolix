package magicdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIURL      = "https://api.tailscale.com"
	defaultHTTPTimeout = 15 * time.Second
	maxAPIResponseSize = 32 * 1024 * 1024
	tokenRefreshSkew   = 2 * time.Minute
)

// Device is the subset of the Tailscale device schema needed for MagicDNS.
type Device struct {
	ID                string   `json:"id"`
	NodeID            string   `json:"nodeId"`
	Name              string   `json:"name"`
	Hostname          string   `json:"hostname"`
	Addresses         []string `json:"addresses"`
	Expires           string   `json:"expires"`
	Authorized        bool     `json:"authorized"`
	KeyExpiryDisabled bool     `json:"keyExpiryDisabled"`
	IsExternal        bool     `json:"isExternal"`
	IsEphemeral       bool     `json:"isEphemeral"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Client retrieves the tailnet device inventory with OAuth client credentials.
type Client struct {
	clientID     string
	clientSecret string
	tailnet      string
	apiURL       string
	httpClient   *http.Client

	tokenMu      sync.Mutex
	token        string
	tokenExpires time.Time
	now          func() time.Time
}

// NewClient creates a production client pinned to Tailscale's API origin.
func NewClient(clientID, clientSecret, tailnet string) (*Client, error) {
	return newClient(clientID, clientSecret, tailnet, defaultAPIURL, nil)
}

func newClient(
	clientID,
	clientSecret,
	tailnet,
	apiURL string,
	httpClient *http.Client,
) (*Client, error) {
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	tailnet = strings.TrimSpace(tailnet)
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if clientID == "" || clientSecret == "" || tailnet == "" {
		return nil, errors.New("magicdns oauth client id, secret, and tailnet are required")
	}
	parsed, err := url.ParseRequestURI(apiURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("magicdns api url is invalid")
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       defaultHTTPTimeout,
			CheckRedirect: rejectRedirect,
		}
	}
	return &Client{
		clientID:     clientID,
		clientSecret: clientSecret,
		tailnet:      tailnet,
		apiURL:       apiURL,
		httpClient:   httpClient,
		now:          time.Now,
	}, nil
}

// ListDevices returns the current tailnet inventory.
func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	devices, unauthorized, err := c.listDevices(ctx)
	if err != nil || !unauthorized {
		return devices, err
	}
	c.invalidateToken()
	devices, unauthorized, err = c.listDevices(ctx)
	if err != nil {
		return nil, err
	}
	if unauthorized {
		return nil, errors.New("tailscale devices request remained unauthorized after token renewal")
	}
	return devices, nil
}

func (c *Client) listDevices(ctx context.Context) ([]Device, bool, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, false, err
	}
	endpoint := c.apiURL + "/api/v2/tailnet/" + url.PathEscape(c.tailnet) + "/devices"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, fmt.Errorf("create tailscale devices request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.do(req)
	if err != nil {
		return nil, false, fmt.Errorf("list tailscale devices: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("list tailscale devices: unexpected status %d", resp.StatusCode)
	}
	var payload struct {
		Devices []Device `json:"devices"`
	}
	if err := decodeLimitedJSON(resp.Body, &payload); err != nil {
		return nil, false, fmt.Errorf("decode tailscale devices: %w", err)
	}
	if payload.Devices == nil {
		payload.Devices = make([]Device, 0)
	}
	return payload.Devices, false, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != "" && c.now().Add(tokenRefreshSkew).Before(c.tokenExpires) {
		return c.token, nil
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.apiURL+"/api/v2/oauth/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("create tailscale token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("request tailscale access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("request tailscale access token: unexpected status %d", resp.StatusCode)
	}
	var token tokenResponse
	if err := decodeLimitedJSON(resp.Body, &token); err != nil {
		return "", fmt.Errorf("decode tailscale access token: %w", err)
	}
	if token.AccessToken == "" || token.ExpiresIn <= 0 {
		return "", errors.New("tailscale access token response is incomplete")
	}
	c.token = token.AccessToken
	c.tokenExpires = c.now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *Client) invalidateToken() {
	c.tokenMu.Lock()
	c.token = ""
	c.tokenExpires = time.Time{}
	c.tokenMu.Unlock()
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	secureClient := *c.httpClient
	secureClient.CheckRedirect = rejectRedirect
	return secureClient.Do(req)
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func decodeLimitedJSON(reader io.Reader, target interface{}) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxAPIResponseSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxAPIResponseSize {
		return fmt.Errorf("response exceeds %d bytes", maxAPIResponseSize)
	}
	return json.Unmarshal(data, target)
}
