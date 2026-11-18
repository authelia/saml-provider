package xmlrv

import (
	"encoding/xml"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestValidate(t *testing.T) {
	docs := []string{
		``,
		`<Root></Root>`,
		`<x:Root></x:Root>`,
		`<x:Root xmlns:x="http://example.com/"></x:Root>`,
		`<x:Root xmlns="http://example.com/"></x:Root>`,
		`<Root xmlns="http://example.com/1" xmlns="http://example.com/2"></Root>`,
		`<?xml version="1.0" encoding="EUC-JP"?><Root></Root>`,
		`<Root>text &quot;hello&quot;</Root>`,
		`<Root><![CDATA[text "hello"]]></Root>`,
		`<!-- comment --><Root/>`,
		`<Root xmlns="http://example.com/1" x:attr="y"/>`,
		`<x:Root xmlns="http://example.com/1" x:attr="y" x:attr2="z"/>`,
		`<x:Root xmlns:x="http://example.com/"><Element xmlns:x="http://example.com/"/></x:Root>`,
		`<Root xmlns="http://example.com/"/>`,
		`&reference;`,
		`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">`,
		`<! ">" <X/>>`,
		`<!name <!-- comment --><nesting <more nesting>>>`,
		"<Root>\r\n</Root>",
		`<a>x</a>y<b/>z`,
		`<?pi data?><a/>`,

		// encoding/xml once changed these in a round trip, and now reads and writes them alike.
		`<Root :="value"/>`,
		`<Root x:="value"/>`,
		`<Root xmlns="x" xmlns:="y"></Root>`,
		`<x:>`,
		`</x:>`,
		`<Root><! <<!-- -->!-- x --> y></Root>`,
	}

	for _, doc := range docs {
		assert.Check(t, Validate([]byte(doc)), "doc: %q", doc)
	}
}

// encoding/xml once changed these in a round trip, and now refuses them.
func TestValidateSyntaxError(t *testing.T) {
	docs := []string{
		`<x::Root/>`,
		`<Root><x::Element></::Element></Root>`,
		`<Root><Element ::attr="foo"></Element></Root>`,
		`<Root></x::Element></Root>`,
		`<Root><!--`,
		`<Root>]]></Root>`,
		`<Root><!-- a -- b --></Root>`,
		`<a:b:c/>`,
	}

	for _, doc := range docs {
		assert.Check(t, is.ErrorType(Validate([]byte(doc)), &xml.SyntaxError{}), "doc: %q", doc)
	}
}

// encoding/xml reads these leniently but can't write them back: it refuses to encode the directive, refuses to read
// back the name it encoded, and encodes empty CDATA as nothing.
func TestValidateUnstableToken(t *testing.T) {
	testCases := []struct {
		doc          string
		line, column int64
	}{
		{"<a><!>DOCTYPE a=></a>", 1, 4},
		{"<a>\n  </b:--d></a>", 2, 3},
		{"<a><![CDATA[]]></a>", 1, 4},
		{"<a>\n<b>\n<![CDATA[]]></b></a>", 3, 1},
		{"<a>\r\n<b>\r\n  <![CDATA[]]></b></a>", 3, 3},
		{"<a>\r<b>\r  <![CDATA[]]></b></a>", 3, 3},
		{"<a>\r\r\n\n<![CDATA[]]></a>", 4, 1},
	}

	for _, tc := range testCases {
		var validationErr ValidationError

		if assert.Check(t, errors.As(Validate([]byte(tc.doc)), &validationErr), "doc: %q", tc.doc) {
			assert.Check(t, is.Equal(tc.line, validationErr.Line), "doc: %q", tc.doc)
			assert.Check(t, is.Equal(tc.column, validationErr.Column), "doc: %q", tc.doc)
		}
	}
}

// Validate runs on documents before their signature is verified. It once allocated an encoder and a decoder, with
// buffers of 4 KiB, for every token, which was about 2,500 bytes for each byte of a document of empty elements.
func TestValidateAllocationsBoundedByInputSize(t *testing.T) {
	const maxBytesPerInputByte = 300

	docs := map[string]string{
		"empty elements": "<r>" + strings.Repeat("<a/>", 50000) + "</r>",
		"elements":       "<r>" + strings.Repeat("<a>x</a>", 50000) + "</r>",
		"attributes":     "<r>" + strings.Repeat(`<s:a xmlns:s="u" s:b="c" d="e"/>`, 10000) + "</r>",
		"comments":       "<r>" + strings.Repeat("<!---->", 50000) + "</r>",
		"directives":     strings.Repeat("<!a>", 50000) + "<r/>",
		"text":           "<r>" + strings.Repeat("x", 200000) + "</r>",
	}

	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			data := []byte(doc)

			var before, after runtime.MemStats

			runtime.GC()
			runtime.ReadMemStats(&before)

			assert.NilError(t, Validate(data))

			runtime.ReadMemStats(&after)

			perByte := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(data))
			assert.Check(t, perByte < maxBytesPerInputByte, "allocated %.0f bytes per input byte", perByte)
		})
	}
}

func BenchmarkValidate(b *testing.B) {
	data := []byte("<r>" + strings.Repeat(`<a b="c">x</a>`, 10000) + "</r>")

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		if err := Validate(data); err != nil {
			b.Fatal(err)
		}
	}
}

// An attribute with the prefix of the element and one with a prefix that isn't declared still come back changed.
func TestValidateRoundtripError(t *testing.T) {
	testCases := map[string]struct {
		doc          string
		source       string
		line, column int64
	}{
		"first line": {
			doc:    `<x:Root xmlns:x="a" x:attr="1" y:b="2"/>`,
			source: `<x:Root xmlns:x="a" x:attr="1" y:b="2"/>`,
			line:   1, column: 1,
		},
		"nested": {
			doc:    "<Root>\r\n  <x:Element xmlns:x=\"a\" x:attr=\"1\" y:b=\"2\"></x:Element>\r\n</Root>",
			source: `<x:Element xmlns:x="a" x:attr="1" y:b="2">`,
			line:   2, column: 3,
		},
		"after text": {
			doc:    "<Root>\n\ntext<x:E xmlns:x=\"a\" x:a=\"1\" y:b=\"2\"/></Root>",
			source: `<x:E xmlns:x="a" x:a="1" y:b="2"/>`,
			line:   3, column: 5,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var validationErr ValidationError

			assert.Assert(t, errors.As(Validate([]byte(tc.doc)), &validationErr))
			assert.Check(t, is.Equal(tc.line, validationErr.Line))
			assert.Check(t, is.Equal(tc.column, validationErr.Column))
			assert.Check(t, is.Equal(tc.source, tc.doc[validationErr.Start:validationErr.End]))

			var roundtripErr RoundtripError

			assert.Assert(t, errors.As(validationErr, &roundtripErr))
			assert.Check(t, is.DeepEqual(tokenize(t, tc.source), roundtripErr.Expected))
		})
	}
}

// The token that was read back is reported as it was read, not as it was fixed to be compared.
func TestValidateRoundtripErrorObserved(t *testing.T) {
	var roundtripErr RoundtripError

	assert.Assert(t, errors.As(Validate([]byte(`<x:Root xmlns:x="a" x:attr="1" y:b="2"/>`)), &roundtripErr))

	observed, ok := roundtripErr.Observed.(xml.StartElement)
	assert.Assert(t, ok)
	assert.Check(t, is.DeepEqual(xml.StartElement{
		Name: xml.Name{Local: "Root"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: "x"},
			{Name: xml.Name{Space: "xmlns", Local: "_xmlns"}, Value: "xmlns"},
			{Name: xml.Name{Space: "_xmlns", Local: "x"}, Value: "a"},
			{Name: xml.Name{Space: "xmlns", Local: "x"}, Value: "x"},
			{Name: xml.Name{Space: "x", Local: "attr"}, Value: "1"},
			{Name: xml.Name{Space: "xmlns", Local: "y"}, Value: "y"},
			{Name: xml.Name{Space: "y", Local: "b"}, Value: "2"},
		},
	}, observed))
}

func TestTokenEquals(t *testing.T) {
	tokens := []xml.Token{
		tokenize(t, `token`),
		tokenize(t, `<!--token-->`),
		tokenize(t, `<!token>`),
		tokenize(t, `</token>`),
		tokenize(t, `<?token?>`),
		tokenize(t, `<token>`),
	}

	for i, token1 := range tokens {
		for j, token2 := range tokens {
			assert.Check(t, is.Equal(i == j, tokenEquals(token1, xml.CopyToken(token2))), "%T and %T", token1, token2)
		}
	}

	assert.Check(t, !tokenEquals(struct{}{}, struct{}{}), "a value that isn't a token never equals")
}

func TestErrorMessages(t *testing.T) {
	assert.Check(t, is.Equal("xmlrv: in token starting at 2:16: unexpected EOF",
		ValidationError{Start: 34, End: 54, Line: 2, Column: 16, err: io.ErrUnexpectedEOF}.Error()))

	assert.Check(t, is.Equal("roundtrip error: expected {{ Foo} []}, observed {{ Bar} []}",
		RoundtripError{Expected: tokenize(t, `<Foo>`), Observed: tokenize(t, `<Bar>`)}.Error()))
}

func tokenize(t *testing.T, s string) xml.Token {
	t.Helper()

	token, err := xml.NewDecoder(strings.NewReader(s)).RawToken()
	assert.NilError(t, err)

	return xml.CopyToken(token)
}
