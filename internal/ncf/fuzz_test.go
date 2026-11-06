package ncf

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// FuzzEntry: parsing never panics, and a parsed entry's canonical spelling
// parses back to itself, in both the authored and the live parser.
func FuzzEntry(f *testing.F) {
	for _, s := range []string{"192.0.2.0/24", "198.51.100.7", "198.51.100.7/32", "2001:db8::/32", "geo::de", "GEO::DE",
		"ASN::64500", "ASN::064500", "192.0.2.1/24", "::ffff:192.0.2.1", "0.0.0.0/0", "::/0", "", " ", "ASN::4294967296"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, parse := range []func(string) (Value, error){ParseAuthored, ParseLive} {
			v, err := parse(s)
			if err != nil {
				continue
			}
			again, err := ParseLive(v.String())
			if err != nil || again.String() != v.String() {
				t.Fatalf("%q canonicalises to %q, which reparses to %q (%v)", s, v.String(), again.String(), err)
			}
		}
	})
}

// FuzzDesiredFile: decoding any bytes never panics, and the canonical form
// is a fixed point: decoding and re-canonicalising it changes nothing.
func FuzzDesiredFile(f *testing.F) {
	f.Add([]byte(`{"schema":"prolexic.desired.v1","accountId":"A-EXAMPLE","ownSpace":{"prefixes":[],"aliases":[]},"aliases":[{"name":"block-v4","id":101,"type":"SOURCE","role":"deny","entries":["192.0.2.0/25",{"cidr":"198.51.100.7","ticket":"T"}]}]}`))
	f.Add([]byte("\xef\xbb\xbf{}"))
	f.Add([]byte(`{"aliases":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		file, _, err := Decode(bytes.NewReader(b))
		if err != nil {
			return
		}
		canon, err := Canonical(file)
		if err != nil {
			return
		}
		again, _, err := Decode(bytes.NewReader(canon))
		if err != nil {
			t.Fatalf("the canonical form doesn't decode: %v\n%s", err, canon)
		}
		twice, err := Canonical(again)
		if err != nil || !bytes.Equal(canon, twice) {
			t.Fatalf("canonical form isn't stable:\n%s\n---\n%s", canon, twice)
		}
	})
}

// FuzzEntriesHash: a set hashes the same in any order, with duplicates, and
// with equivalent spellings (a bare address and its /32).
func FuzzEntriesHash(f *testing.F) {
	f.Add("192.0.2.0/25,198.51.100.7,GEO::DE")
	f.Add("2001:db8::1,ASN::64500")
	f.Fuzz(func(t *testing.T, list string) {
		entries := strings.Split(list, ",")
		var respelled []string
		for _, e := range entries {
			if v, err := ParseLive(e); err == nil {
				e = v.String() // the canonical spelling of the same entry
			}
			respelled = append(respelled, e)
		}
		shuffled := append(slices.Clone(respelled), respelled...) // duplicates
		slices.Reverse(shuffled)
		if entriesHash(entries) != entriesHash(shuffled) {
			t.Fatalf("%q and %q hash differently", entries, shuffled)
		}
	})
}
