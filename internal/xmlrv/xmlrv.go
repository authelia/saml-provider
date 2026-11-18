// Package xmlrv rejects an XML document with a token that encoding/xml doesn't read back unchanged once it has
// written it. Such a token is one that parsers may disagree about, so rejecting it before the document is parsed is a
// mitigation for some differences between parsers.
package xmlrv

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
)

// RoundtripError is a token which encoding/xml doesn't read back as it was.
type RoundtripError struct {
	Expected, Observed xml.Token
}

// Error returns the token and what it was read back as.
func (err RoundtripError) Error() string {
	return fmt.Sprintf("roundtrip error: expected %v, observed %v", err.Expected, err.Observed)
}

// ErrOverflow is a token whose encoding is read back as the token followed by more input.
var ErrOverflow = errors.New("roundtrip error: unexpected input after token")

// ValidationError is a token of a document that failed its round trip, and where it is in the document. Start and
// End are the offsets of the bytes of the token, and Line and Column are where it starts, counted from 1.
type ValidationError struct {
	Start, End, Line, Column int64
	err                      error
}

// Error returns where the token starts and why it failed its round trip.
func (err ValidationError) Error() string {
	return fmt.Sprintf("xmlrv: in token starting at %d:%d: %s", err.Line, err.Column, err.err.Error())
}

// Unwrap returns why the token failed its round trip.
func (err ValidationError) Unwrap() error {
	return err.err
}

// Validate returns nil if every token of data survives a round trip through encoding/xml unchanged, a
// ValidationError for the first token that doesn't, or the error of encoding/xml if data can't be read.
//
// It runs on documents before their signature is verified, so what it allocates is a small multiple of the size
// of data: the encoder and the decoder that check each token share their buffers with the tokens before.
func Validate(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	decoder.CharsetReader = identityCharsetReader

	c := newChecker()
	offset := int64(0)

	for {
		token, err := decoder.RawToken()

		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}

		if err = c.check(token); err != nil {
			line, column := position(data, offset)

			return ValidationError{
				Start:  offset,
				End:    decoder.InputOffset(),
				Line:   line,
				Column: column,
				err:    err,
			}
		}

		offset = decoder.InputOffset()
	}
}

// position returns the line and the column, counted from 1, of offset in data. A carriage return, a line feed, and a
// carriage return followed by a line feed each end a line, as XML 1.0 section 2.11 reads them.
func position(data []byte, offset int64) (line, column int64) {
	line, lineStart := 1, int64(0)

	for i := int64(0); i < offset; i++ {
		switch data[i] {
		case '\r':
			if i+1 < offset && data[i+1] == '\n' {
				i++
			}
		case '\n':
		default:
			continue
		}

		line++
		lineStart = i + 1
	}

	return line, offset - lineStart + 1
}

// identityCharsetReader reads every charset as it is, as only the round trip of the bytes matters.
func identityCharsetReader(_ string, input io.Reader) (io.Reader, error) {
	return input, nil
}

// sentinel follows the encoding of CharData. The decoder reads CharData up to the next '<', and without one it would
// reach the end of its input, which it doesn't recover from. Every other token ends with a '>', past which the
// decoder reads nothing.
var sentinel = []byte("<_/>")

// checker encodes a token and reads it back, with the same buffers and decoder from one token to the next.
type checker struct {
	encoded bytes.Buffer
	writer  *bufio.Writer

	// input gives the encoded tokens to decoder.
	input   feed
	decoder *xml.Decoder
}

func newChecker() *checker {
	c := &checker{}
	c.writer = bufio.NewWriter(&c.encoded)
	c.decoder = xml.NewDecoder(&c.input)
	c.decoder.CharsetReader = identityCharsetReader

	return c
}

// check encodes the token and reads it back, and returns an error if what is read back differs.
func (c *checker) check(before xml.Token) error {
	// An encoder of its own for each token, so that no prefix it declared carries over to the next. It writes to
	// c.writer, which xml.NewEncoder uses rather than allocating a buffer of its own.
	c.encoded.Reset()

	encoder := xml.NewEncoder(c.writer)

	end, isEnd := before.(xml.EndElement)

	// The encoder wants a StartElement for each EndElement.
	if isEnd {
		if err := encoder.EncodeToken(xml.StartElement{Name: end.Name}); err != nil {
			return err
		}
	}

	if err := encoder.EncodeToken(before); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}

	_, isCharData := before.(xml.CharData)

	encodedLen := int64(c.encoded.Len())

	if isCharData {
		c.input.reset(c.encoded.Bytes(), sentinel)
	} else {
		c.input.reset(c.encoded.Bytes(), nil)
	}

	start := c.decoder.InputOffset()

	// Skip the StartElement that was added.
	if isEnd {
		if _, err := c.decoder.RawToken(); err != nil {
			return err
		}
	}

	after, err := c.decoder.RawToken()
	if err != nil {
		return err
	}

	// The tokens are copied, as those of a decoder are only valid until it is next read.
	if !tokenEquals(before, after) {
		return RoundtripError{Expected: xml.CopyToken(before), Observed: xml.CopyToken(after)}
	}

	if c.decoder.InputOffset()-start != encodedLen {
		return ErrOverflow
	}

	if isCharData {
		return c.readSentinel()
	}

	return nil
}

// readSentinel reads the sentinel after CharData, which leaves the decoder at the end of its input.
func (c *checker) readSentinel() error {
	name := xml.Name{Local: "_"}

	token, err := c.decoder.RawToken()
	if err != nil {
		return err
	}

	if start, ok := token.(xml.StartElement); !ok || start.Name != name || len(start.Attr) != 0 {
		return ErrOverflow
	}

	if token, err = c.decoder.RawToken(); err != nil {
		return err
	}

	if end, ok := token.(xml.EndElement); !ok || end.Name != name {
		return ErrOverflow
	}

	return nil
}

// feed is an [io.ByteReader] over an encoded token and the sentinel. The decoder doesn't buffer an [io.ByteReader], so
// it reads no further than the end of what it is given.
type feed struct {
	buf []byte
	off int
}

func (f *feed) reset(token, sentinel []byte) {
	f.buf = append(append(f.buf[:0], token...), sentinel...)
	f.off = 0
}

// ReadByte returns the next byte, or [io.EOF] at the end.
func (f *feed) ReadByte() (byte, error) {
	if f.off >= len(f.buf) {
		return 0, io.EOF
	}

	b := f.buf[f.off]
	f.off++

	return b, nil
}

// Read reads up to len(p) bytes, or returns [io.EOF] at the end.
func (f *feed) Read(p []byte) (int, error) {
	if f.off >= len(f.buf) {
		return 0, io.EOF
	}

	n := copy(p, f.buf[f.off:])
	f.off += n

	return n, nil
}

// tokenEquals returns true if after is before read back, allowing for the namespace prefixes that encoding/xml
// rewrites.
func tokenEquals(before, after xml.Token) bool {
	switch t1 := before.(type) {
	case xml.CharData:
		t2, ok := after.(xml.CharData)

		return ok && bytes.Equal(t1, t2)
	case xml.Comment:
		t2, ok := after.(xml.Comment)

		return ok && bytes.Equal(t1, t2)
	case xml.Directive:
		t2, ok := after.(xml.Directive)

		return ok && bytes.Equal(t1, t2)
	case xml.EndElement:
		t2, ok := after.(xml.EndElement)

		// The prefix is erased, so only the local name is compared.
		return ok && t1.Name.Local == t2.Name.Local && t2.Name.Space == ""
	case xml.ProcInst:
		t2, ok := after.(xml.ProcInst)

		return ok && t1.Target == t2.Target && bytes.Equal(t1.Inst, t2.Inst)
	case xml.StartElement:
		t2, ok := after.(xml.StartElement)

		return ok && startElementEquals(t1, t2)
	default:
		return false
	}
}

// startElementEquals returns true if after is before read back, once the xmlns attributes that encoding/xml adds
// for the prefixes are undone. The order of the attributes is kept.
func startElementEquals(before, after xml.StartElement) bool {
	// The attributes are fixed in a copy, as after is reported in the error as it was read.
	after.Attr = slices.Clone(after.Attr)

	fixNamespacePrefixes(&before, &after)

	return before.Name == after.Name && slices.Equal(before.Attr, after.Attr)
}

// fixNamespacePrefixes undoes in after the xmlns attributes that encoding/xml adds for the prefixes of the element
// and of its attributes, so that it can be compared with before.
func fixNamespacePrefixes(before, after *xml.StartElement) {
	if len(after.Attr) <= len(before.Attr) {
		return
	}

	// An erased prefix of the element has its xmlns attribute first.
	if before.Name.Space != "" && after.Name.Space == "" && after.Attr[0].Name == (xml.Name{Local: "xmlns"}) {
		after.Name.Space = after.Attr[0].Value
		after.Attr = after.Attr[1:]
	}

	// The xmlns attribute of the prefix of an attribute comes just before it.
	for len(after.Attr) > len(before.Attr) && len(after.Attr) > 1 {
		i := 1

		for ; i < len(after.Attr); i++ {
			if after.Attr[i-1].Name.Space == "xmlns" && after.Attr[i-1].Name.Local == after.Attr[i].Name.Space {
				break
			}
		}

		if i == len(after.Attr) {
			return
		}

		prefix, space := after.Attr[i-1].Name.Local, after.Attr[i-1].Value

		after.Attr = append(after.Attr[:i-1], after.Attr[i:]...)

		for j := range after.Attr {
			if after.Attr[j].Name.Space == prefix {
				after.Attr[j].Name.Space = space
			}
		}
	}
}
