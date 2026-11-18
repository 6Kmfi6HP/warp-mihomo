// Package health checks that traffic from this process leaves through WARP.
// Docker runs it as a separate process in the mihomo network namespace, so
// its sockets are not marked and enter the TUN.
package health

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const traceURL = "https://1.1.1.1/cdn-cgi/trace"

// Check returns nil when the trace says warp=on.
func Check() (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Get(traceURL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trace %s", res.Status)
	}
	ip, warp := "", ""
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			ip = v
		case "warp":
			warp = v
		}
	}
	if warp != "on" {
		return "", fmt.Errorf("warp=%s ip=%s", warp, ip)
	}
	return fmt.Sprintf("warp=on ip=%s", ip), nil
}
