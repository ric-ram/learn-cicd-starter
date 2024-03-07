package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetApiKeySuccess(t *testing.T) {
	tests := []struct {
		auth          string
		value         string
		expectedToken string
	}{
		{
			auth:          "Authorization",
			value:         "ApiKey 123",
			expectedToken: "123",
		},
		{
			auth:          "Authorization",
			value:         "ApiKey thisisanapikey",
			expectedToken: "thisisanapikey",
		},
		{
			auth:          "Authorization",
			value:         "ApiKey hello-how-are-you",
			expectedToken: "hello-how-are-you",
		},
		{
			auth:          "Authorization",
			value:         "ApiKey testing_api_key",
			expectedToken: "testing_api_key",
		},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(tc.auth, tc.value)

		header := req.Header
		actualToken, err := GetAPIKey(header)
		if err != nil {
			t.Error(err)
			continue
		}
		if actualToken != tc.expectedToken {
			t.Errorf("%s doesn't match %s", actualToken, tc.expectedToken)
		}
	}
}

func TestGetApiKeyFail(t *testing.T) {
	tests := []struct {
		auth          string
		value         string
		expectedError error
	}{
		{
			auth:          "Auth",
			value:         "ApiKey 123",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			auth:          "Authorization",
			value:         "Apikey 123",
			expectedError: ErrMalformedHeader,
		},
		{
			auth:          "Auhtorization",
			value:         "ApiKey 123",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			auth:          "Authorization",
			value:         "ApiToken 123",
			expectedError: ErrMalformedHeader,
		},
	}
	actualErrors := []error{
		ErrNoAuthHeaderIncluded,
		ErrMalformedHeader,
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(tc.auth, tc.value)

		header := req.Header
		_, err := GetAPIKey(header)
		if !errors.Is(actualErrors[0], err) || !errors.Is(actualErrors[1], err) {
			t.Errorf("%v is not the correct error", err)
			continue
		}
	}
}
