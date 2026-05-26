package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 180 * time.Second}}
}

func (c *Client) FetchBytes(ctx context.Context, url string) ([]byte, error) {
	if isLocalPath(url) {
		return os.ReadFile(strings.TrimPrefix(url, "file://"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackroute/1.0")
	req.Header.Set("Accept", "text/plain, application/json, */*")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func isLocalPath(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "file://") {
		return true
	}
	u, err := url.Parse(raw)
	if err == nil && u.Scheme != "" {
		return false
	}
	return strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../")
}
