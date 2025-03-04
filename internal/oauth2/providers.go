package oauth2

import (
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// GetGoogleConfig returns the OAuth2 config for Google
func GetGoogleConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://mail.google.com/",
		},
		Endpoint: google.Endpoint,
	}
}

// GetMicrosoftConfig returns the OAuth2 config for Microsoft
func GetMicrosoftConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://outlook.office.com/IMAP.AccessAsUser.All",
			"offline_access",
		},
		Endpoint: microsoft.AzureADEndpoint("common"),
	}
}

// GetProviderConfig returns the OAuth2 config for a specific provider
func GetProviderConfig(provider, clientID, clientSecret, redirectURL string) (*oauth2.Config, error) {
	switch provider {
	case "google":
		return GetGoogleConfig(clientID, clientSecret, redirectURL), nil
	case "microsoft":
		return GetMicrosoftConfig(clientID, clientSecret, redirectURL), nil
	default:
		return nil, fmt.Errorf("unsupported OAuth2 provider: %s", provider)
	}
} 