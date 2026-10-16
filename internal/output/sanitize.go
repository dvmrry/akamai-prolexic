package output

import (
	"fmt"
	"io"
	"unicode/utf8"
)

// safeWriter makes control characters visible and harmless: text output
// carries API-supplied strings, and a raw escape sequence in one would act on
// the terminal or forge lines in a CI log. C0 controls except \n and \t, DEL
// and C1 controls (U+0080 to U+009F) are written as escaped text. A raw
// 0x80-0x9f byte that is not valid UTF-8 is escaped too, since an 8-bit
// terminal reads it as a C1 control.
type safeWriter struct {
	w       io.Writer
	pending []byte // an incomplete UTF-8 sequence from the previous Write
}

func (s *safeWriter) Write(p []byte) (int, error) {
	in := p
	if len(s.pending) > 0 {
		in = append(s.pending, p...)
		s.pending = nil
	}
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); {
		b := in[i]
		if b < utf8.RuneSelf {
			if (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f {
				out = fmt.Appendf(out, `\x%02x`, b)
			} else {
				out = append(out, b)
			}
			i++
			continue
		}
		if !utf8.FullRune(in[i:]) {
			s.pending = append([]byte(nil), in[i:]...)
			break
		}
		r, size := utf8.DecodeRune(in[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			if b >= 0x80 && b <= 0x9f {
				out = fmt.Appendf(out, `\x%02x`, b)
			} else {
				out = append(out, b)
			}
		case r >= 0x80 && r <= 0x9f:
			out = fmt.Appendf(out, `\u%04x`, r)
		default:
			out = append(out, in[i:i+size]...)
		}
		i += size
	}
	if _, err := s.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// flush writes out a sequence left incomplete at the end of the document.
func (s *safeWriter) flush() error {
	if len(s.pending) == 0 {
		return nil
	}
	rest := s.pending
	s.pending = nil
	var out []byte
	for _, b := range rest {
		if b >= 0x80 && b <= 0x9f {
			out = fmt.Appendf(out, `\x%02x`, b)
		} else {
			out = append(out, b)
		}
	}
	_, err := s.w.Write(out)
	return err
}
