package devicecode

import (
	"encoding/json"
	"testing"
)

func TestFlexIntUnmarshal(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    FlexInt
		wantErr bool
	}{
		{"v2 number", `3600`, 3600, false},
		{"v1 quoted string", `"3600"`, 3600, false},
		{"zero number", `0`, 0, false},
		{"zero string", `"0"`, 0, false},
		{"null", `null`, 0, false},
		{"embedded in object number", `{"expires_in":4871}`, 4871, false},
		{"embedded in object string", `{"expires_in":"4871"}`, 4871, false},
		{"non-numeric string errors", `"abc"`, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Support both the bare-value and object-embedded forms.
			if c.name == "embedded in object number" || c.name == "embedded in object string" {
				var obj struct {
					ExpiresIn FlexInt `json:"expires_in"`
				}
				err := json.Unmarshal([]byte(c.in), &obj)
				if (err != nil) != c.wantErr {
					t.Fatalf("Unmarshal(%s) err=%v wantErr=%v", c.in, err, c.wantErr)
				}
				if !c.wantErr && obj.ExpiresIn != c.want {
					t.Fatalf("Unmarshal(%s) = %d, want %d", c.in, obj.ExpiresIn, c.want)
				}
				return
			}
			var got FlexInt
			err := json.Unmarshal([]byte(c.in), &got)
			if (err != nil) != c.wantErr {
				t.Fatalf("Unmarshal(%s) err=%v wantErr=%v", c.in, err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("Unmarshal(%s) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

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
