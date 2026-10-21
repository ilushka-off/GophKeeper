package gateway_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/server/gateway"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

func newGateway(t *testing.T) *httptest.Server {
	t.Helper()
	srv := testutil.StartServer(t)
	gw, err := gateway.New(context.Background(), srv.Services, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(gw.Close)
	ts := httptest.NewServer(gw)
	t.Cleanup(ts.Close)
	return ts
}

// call sends a JSON request and decodes the JSON response into a map.
func call(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rd)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return resp.StatusCode, out
}

func TestSwaggerSpec(t *testing.T) {
	ts := newGateway(t)
	resp, err := http.Get(ts.URL + gateway.SpecPath)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var spec struct {
		Swagger string                    `json:"swagger"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&spec))
	assert.Equal(t, "2.0", spec.Swagger)
	for _, p := range []string{"/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/records", "/api/v1/sync/push"} {
		assert.Contains(t, spec.Paths, p)
	}
}

func TestRESTFlow(t *testing.T) {
	ts := newGateway(t)
	api := ts.URL + "/api/v1"
	salt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))

	code, out := call(t, http.MethodPost, api+"/auth/register", "",
		map[string]any{"login": "ilya", "password": "login-password", "kdfSalt": salt})
	require.Equal(t, http.StatusOK, code, out)

	code, out = call(t, http.MethodGet, api+"/auth/salt/ilya", "", nil)
	require.Equal(t, http.StatusOK, code, out)
	assert.Equal(t, salt, out["kdfSalt"])

	code, out = call(t, http.MethodPost, api+"/auth/login", "",
		map[string]any{"login": "ilya", "password": "login-password"})
	require.Equal(t, http.StatusOK, code, out)
	token := out["tokens"].(map[string]any)["accessToken"].(string)
	require.NotEmpty(t, token)

	code, _ = call(t, http.MethodGet, api+"/records", "", nil)
	assert.Equal(t, http.StatusUnauthorized, code, "records need a token")

	id := uuid.NewString()
	payload := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	code, out = call(t, http.MethodPost, api+"/sync/push", token, map[string]any{
		"changes": []map[string]any{{"id": id, "type": "RECORD_TYPE_TEXT", "payload": payload}},
	})
	require.Equal(t, http.StatusOK, code, out)
	assert.Len(t, out["accepted"], 1)

	code, out = call(t, http.MethodGet, api+"/records/"+id, token, nil)
	require.Equal(t, http.StatusOK, code, out)
	rec := out["record"].(map[string]any)
	assert.Equal(t, payload, rec["payload"])
	assert.Equal(t, "RECORD_TYPE_TEXT", rec["type"])

	code, out = call(t, http.MethodGet, api+"/sync/pull?since=0", token, nil)
	require.Equal(t, http.StatusOK, code, out)
	assert.Len(t, out["records"], 1)

	code, _ = call(t, http.MethodGet, api+"/records/"+uuid.NewString(), token, nil)
	assert.Equal(t, http.StatusNotFound, code)
}
