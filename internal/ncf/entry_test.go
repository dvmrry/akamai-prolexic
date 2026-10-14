package ncf

import (
	"slices"
	"strings"
	"testing"
)

func TestParseAuthored(t *testing.T) {
	tests := []struct {
		in, want, err string
	}{
		{in: "192.0.2.0/24", want: "192.0.2.0/24"},
		{in: "192.0.2.7", want: "192.0.2.7/32"},
		{in: "2001:db8::1", want: "2001:db8::1/128"},
		{in: "2001:DB8:0::/48", want: "2001:db8::/48"},
		{in: "::ffff:192.0.2.0/120", want: "192.0.2.0/24"},
		{in: "GEO::us", want: "GEO::US"},
		{in: "geo::GB", want: "GEO::GB"},
		{in: "ASN::64500", want: "ASN::64500"},
		{in: "192.0.2.1/24", err: "host bits set; did you mean 192.0.2.0/24"},
		{in: "GEO:: US", err: "nothing but the value may follow GEO::"},
		{in: "GEO::XX", err: "not an ISO 3166-1 alpha-2"},
		{in: "GEO::USA", err: "not an ISO 3166-1 alpha-2"},
		{in: "ASN::AS64500", err: "ASN must be a number"},
		{in: "ASN::0", err: "ASN must be a number"},
		{in: " 192.0.2.0/24", err: "surrounding whitespace"},
		{in: "192.0.2.0/33", err: "not a prefix"},
		{in: "fe80::1%eth0", err: "zoned"},
		{in: "", err: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := ParseAuthored(tt.in)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil || v.String() != tt.want {
				t.Errorf("= %v, %v; want %s", v, err, tt.want)
			}
		})
	}
}

func TestParseLiveMasksHostBits(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1/24": "192.0.2.0/24",
		" 192.0.2.9 ":  "192.0.2.9/32",
		"geo::de":      "GEO::DE",
	} {
		v, err := ParseLive(in)
		if err != nil || v.String() != want {
			t.Errorf("ParseLive(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
}

func TestCompareOrdersV4V6GeoASN(t *testing.T) {
	in := []string{"ASN::7", "GEO::US", "2001:db8::/32", "198.51.100.0/24", "ASN::64500", "192.0.2.0/25", "192.0.2.0/24", "GEO::DE"}
	var vs []Value
	for _, s := range in {
		v, _ := ParseAuthored(s)
		vs = append(vs, v)
	}
	slices.SortFunc(vs, Compare)
	var got []string
	for _, v := range vs {
		got = append(got, v.String())
	}
	want := "192.0.2.0/24 192.0.2.0/25 198.51.100.0/24 2001:db8::/32 GEO::DE GEO::US ASN::7 ASN::64500"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v", got)
	}
}

func TestCountryList(t *testing.T) {
	if len(countries) != 249 {
		t.Errorf("%d ISO 3166-1 alpha-2 codes, want 249", len(countries))
	}
}
