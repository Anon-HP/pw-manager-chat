package service

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

func isPasswordPwned(ctx context.Context, password string) (bool, error) {
	h := sha1.New()
	h.Write([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	prefix := fullHash[:5]
	suffix := fullHash[5:]

	apiUrl := "https://api.pwnedpasswords.com/range/" + prefix

	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, apiUrl, nil)

	if err != nil {
		return false, err
	}

	req.Header.Set("Add-Padding", "true")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == suffix {
			// Found in breach database
			return true, nil
		}
	}

	return false, nil
}
