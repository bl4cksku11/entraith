package devicecode

import "testing"

func TestV1Resource(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"bare URL", "https://graph.microsoft.com", "https://graph.microsoft.com"},
		{"URN", "urn:vault.azure.net", "urn:vault.azure.net"},
		{"v2 default scope (the AADSTS500011 case)",
			"https://graph.microsoft.com/.default offline_access openid profile",
			"https://graph.microsoft.com"},
		{"single v2 .default", "https://vault.azure.net/.default", "https://vault.azure.net"},
		{"multi-token, .default in later token",
			"https://graph.microsoft.com User.Read.All",
			"https://graph.microsoft.com"},
		{"plain v2 scope string falls back to Graph",
			"offline_access openid profile",
			"https://graph.microsoft.com"},
		{"empty falls back to Graph", "", "https://graph.microsoft.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := v1Resource(c.in); got != c.want {
				t.Fatalf("v1Resource(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
