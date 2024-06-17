package types

import (
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

func TestParseCustomHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "single value",
			input: "a:b",
			want:  map[string]string{"a": "b"},
		},
		{
			name:  "empty string",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "empty value",
			input: "a:",
			want:  map[string]string{"a": ""},
		},
		{
			name:  "double input",
			input: "a:b,c:d",
			want:  map[string]string{"a": "b", "c": "d"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strsl := goflags.StringSlice{}
			for _, v := range strings.Split(tt.input, ",") {
				//nolint
				strsl.Set(v)
			}
			opt := Options{CustomHeaders: strsl}
			got := opt.ParseCustomHeaders()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseHeadlessOptionalArguments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "single value",
			input: "a=b",
			want:  map[string]string{"a": "b"},
		},
		{
			name:  "empty string",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "empty key",
			input: "=b",
			want:  map[string]string{},
		},
		{
			name:  "empty value",
			input: "a=",
			want:  map[string]string{},
		},
		{
			name:  "double input",
			input: "a=b,c=d",
			want:  map[string]string{"a": "b", "c": "d"},
		},
		{
			name:  "duplicated input",
			input: "a=b,a=b",
			want:  map[string]string{"a": "b"},
		},
		{
			name:  "values with dash with boolean flag at the end",
			input: "--a=a/b,c/d--z--n--m/a,--c=k,--h",
			want:  map[string]string{"--a": "a/b,c/d--z--n--m/a", "--c": "k", "--h": ""},
		},
		{
			name:  "values with dash boolean flag at the beginning",
			input: "--h,--a=a/b,c/d--z--n--m/a,--c=k",
			want:  map[string]string{"--h": "", "--a": "a/b,c/d--z--n--m/a", "--c": "k"},
		},
		{
			name:  "values with dash boolean flag in the middle",
			input: "--a=a/b,c/d--z--n--m/a,--h,--c=k",
			want:  map[string]string{"--a": "a/b,c/d--z--n--m/a", "--h": "", "--c": "k"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strsl := goflags.StringSlice{}
			for _, v := range strings.Split(tt.input, ",") {
				//nolint
				strsl.Set(v)
			}
			opt := Options{HeadlessOptionalArguments: strsl}
			got := opt.ParseHeadlessOptionalArguments()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLoadCookiesBrowser(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []*proto.NetworkCookie
	}{
		{
			name:  "Name value with domain",
			input: "foo=bar; Domain=example.com\nbar=foo; Domain=bar.example.com",
			want: []*proto.NetworkCookie{
				{
					Name:   "foo",
					Value:  "bar",
					Domain: "example.com",
				},
				{
					Name:   "bar",
					Value:  "foo",
					Domain: "bar.example.com",
				},
			},
		},
		{
			name:  "Name value with domain and expires",
			input: "foo=bar; Domain=example.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT\nbar=foo; Domain=bar.example.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
			want: []*proto.NetworkCookie{
				{
					Name:    "foo",
					Value:   "bar",
					Domain:  "example.com",
					Expires: proto.TimeSinceEpoch(1445412480),
				},
				{
					Name:    "bar",
					Value:   "foo",
					Domain:  "bar.example.com",
					Expires: proto.TimeSinceEpoch(1445412480),
				},
			},
		},
		{
			name:  "Name value with domain, expires, path, secure, httpOnly",
			input: "foo=bar; Domain=example.com; Expires=Thu, 20 Jun 2024 14:46:26 GMT; Path=/; Secure; HttpOnly\nbar=foo; Domain=bar.example.com; Expires=Thu, 20 Jun 2024 14:46:26 GMT; Path=/",
			want: []*proto.NetworkCookie{
				{
					Name:     "foo",
					Value:    "bar",
					Domain:   "example.com",
					Expires:  proto.TimeSinceEpoch(1718894786),
					Path:     "/",
					Secure:   true,
					HTTPOnly: true,
				},
				{
					Name:     "bar",
					Value:    "foo",
					Domain:   "bar.example.com",
					Expires:  proto.TimeSinceEpoch(1718894786),
					Path:     "/",
					Secure:   false,
					HTTPOnly: false,
				},
			},
		},
		{
			name:  "Name value with domain, expires, path, secure, httpOnly and SameSite",
			input: "foo=bar; Domain=example.com; Expires=Thu, 20 Jun 2024 14:46:26 GMT; Path=/; Secure; HttpOnly; SameSite=None\nfoo=bar; Domain=example.com; Expires=Thu, 20 Jun 2024 14:46:26 GMT; Path=/; Secure; HttpOnly; SameSite=Strict\nfoo=bar; Domain=example.com; Expires=Thu, 20 Jun 2024 14:46:26 GMT; Path=/; Secure; HttpOnly; SameSite=Lax",
			want: []*proto.NetworkCookie{
				{
					Name:     "foo",
					Value:    "bar",
					Domain:   "example.com",
					Expires:  proto.TimeSinceEpoch(1718894786),
					Path:     "/",
					Secure:   true,
					HTTPOnly: true,
					SameSite: proto.NetworkCookieSameSiteNone,
				},
				{
					Name:     "foo",
					Value:    "bar",
					Domain:   "example.com",
					Expires:  proto.TimeSinceEpoch(1718894786),
					Path:     "/",
					Secure:   true,
					HTTPOnly: true,
					SameSite: proto.NetworkCookieSameSiteStrict,
				},
				{
					Name:     "foo",
					Value:    "bar",
					Domain:   "example.com",
					Expires:  proto.TimeSinceEpoch(1718894786),
					Path:     "/",
					Secure:   true,
					HTTPOnly: true,
					SameSite: proto.NetworkCookieSameSiteLax,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strsl := goflags.StringSlice{}
			for _, v := range strings.Split(tt.input, "\n") {
				//nolint
				strsl.Set(v)
			}
			opt := Options{LoadCookiesBrowser: strsl}
			got := opt.ParseLoadCookiesBrowser()
			require.Equal(t, tt.want, got)
		})
	}

}
