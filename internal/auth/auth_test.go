package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string // compare error messages
	}{
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "Malformed Authorization Header - Empty",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "Malformed Authorization Header - No ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Malformed Authorization Header - Only Prefix",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:   "my-secret-key",
			expectedError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}

			if err != nil && tc.expectedError == "" {
				t.Errorf("unexpected error: %v", err)
			} else if err == nil && tc.expectedError != "" {
				t.Errorf("expected error %q but got nil", tc.expectedError)
			} else if err != nil && err.Error() != tc.expectedError {
				t.Errorf("expected error %q, got %q", tc.expectedError, err.Error())
			}
		})
	}
}
