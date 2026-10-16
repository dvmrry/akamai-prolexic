// Package textsafe recognises characters that act on a display, or hide in
// it, instead of showing: the ones a copy-paste carries in unseen.
package textsafe

import "unicode"

// Invisible reports whether r doesn't show as itself:
//   - C0 controls except tab and newline, DEL and C1 controls
//   - format characters (Cf): bidi overrides and isolates, which can visually
//     reverse a line, zero-width characters, the BOM, tag characters
//   - the line and paragraph separators
//   - variation selectors other than the text and emoji presentation ones,
//     and the other default-ignorable characters (Hangul fillers, the
//     combining grapheme joiner): no glyph, so they can smuggle text
func Invisible(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\t' && r != '\n'
	case r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r < 0xa0:
		return false
	case r == 0x2028 || r == 0x2029:
		return true
	case r == 0xfe0e || r == 0xfe0f:
		return false
	}
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}

// Find returns the first invisible character in s and its byte offset, or
// ok false.
func Find(s string) (r rune, at int, ok bool) {
	for i, c := range s {
		if Invisible(c) {
			return c, i, true
		}
	}
	return 0, 0, false
}
