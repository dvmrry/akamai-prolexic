package textsafe

import "testing"

func TestInvisible(t *testing.T) {
	hidden := []rune{
		0x00, 0x0d, 0x1b, 0x7f, 0x85, 0x9b, // C0 but tab and newline, DEL, C1
		0xad, 0x200b, 0x200d, 0x202e, 0x2066, 0xfeff, 0xe0041, // Cf: soft hyphen, zero-width, bidi, BOM, tag
		0x2028, 0x2029, // separators
		0xfe00, 0xe0100, // variation selectors
		0x034f, 0x115f, 0x3164, 0xffa0, // other default-ignorable
	}
	for _, r := range hidden {
		if !Invisible(r) {
			t.Errorf("U+%04X: not invisible", r)
		}
	}
	shown := []rune{'\t', '\n', ' ', 'a', 0xa0, 0xe9, 0x2013, 0x2192, 0x4e2d, 0x1f642, 0xfe0f, 0x0430}
	for _, r := range shown {
		if Invisible(r) {
			t.Errorf("U+%04X: invisible", r)
		}
	}
}

func TestFind(t *testing.T) {
	if r, at, ok := Find("ab" + string(rune(0x200b)) + "c"); !ok || r != 0x200b || at != 2 {
		t.Errorf("Find = U+%04X, %d, %v", r, at, ok)
	}
	if _, _, ok := Find("plain é"); ok {
		t.Error("Find found one in plain text")
	}
}
