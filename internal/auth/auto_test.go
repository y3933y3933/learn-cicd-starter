package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			headers:       http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey:   "my-secret-ke",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header",
			headers:       http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Incomplete Authorization Header",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		key, err := GetAPIKey(tt.headers)
		if key != tt.expectedKey {
			t.Errorf("expected key %q, got %q", tt.expectedKey, key)
		}

		if err != nil && tt.expectedError != nil {
			if err.Error() != tt.expectedError.Error() {
				t.Errorf("expected error %q, got %q", tt.expectedError, err)
			}
		} else if err != tt.expectedError {
			t.Errorf("expected error %q, got %q", tt.expectedError, err)
		}
	}
}
