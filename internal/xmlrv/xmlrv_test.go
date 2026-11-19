package xmlrv

import (
	"encoding/xml"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

		// The xmlns attributes that encoding/xml adds for these are undone in the order it adds them. They were
		// once refused, as the xmlns attribute of the document was undone in the place of one that was added.
		`<x:Root xmlns:x="a" x:attr="1" y:b="2"/>`,
		`<a:e xmlns:a="u" xmlns:b="v" b:x="1" a:y="2" b:z="3" c="4" xmlns:_xmlns="w" _xmlns:q="5"/>`,
	}

	for _, doc := range docs {
		assert.NoError(t, Validate([]byte(doc)), "doc: %q", doc)
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
		var syntaxErr *xml.SyntaxError
		assert.ErrorAs(t, Validate([]byte(doc)), &syntaxErr, "doc: %q", doc)
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

		if assert.True(t, errors.As(Validate([]byte(tc.doc)), &validationErr), "doc: %q", tc.doc) {
			assert.Equal(t, tc.line, validationErr.Line, "doc: %q", tc.doc)
			assert.Equal(t, tc.column, validationErr.Column, "doc: %q", tc.doc)
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

			require.NoError(t, Validate(data))

			runtime.ReadMemStats(&after)

			perByte := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(data))
			assert.True(t, perByte < maxBytesPerInputByte, "allocated %.0f bytes per input byte", perByte)
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
			doc:    `<a><![CDATA[]]></a>`,
			source: `<![CDATA[]]>`,
			line:   1, column: 4,
		},
		"nested": {
			doc:    "<Root>\r\n  <a><![CDATA[]]></a>\r\n</Root>",
			source: `<![CDATA[]]>`,
			line:   2, column: 6,
		},
		"after text": {
			doc:    "<Root>\n\ntext<![CDATA[]]></Root>",
			source: `<![CDATA[]]>`,
			line:   3, column: 5,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var validationErr ValidationError

			require.True(t, errors.As(Validate([]byte(tc.doc)), &validationErr))
			assert.Equal(t, tc.line, validationErr.Line)
			assert.Equal(t, tc.column, validationErr.Column)
			assert.Equal(t, tc.source, tc.doc[validationErr.Start:validationErr.End])

			var roundtripErr RoundtripError

			require.True(t, errors.As(validationErr, &roundtripErr))
			assert.Equal(t, tokenize(t, tc.source), roundtripErr.Expected)
		})
	}
}

// The token that was read back is reported as it was read, not as it was fixed to be compared.
// The token that was read back is reported as it was read, so it is left as it was when it is fixed to be compared.
func TestStartElementEqualsLeavesAfterAsRead(t *testing.T) {
	before := tokenize(t, `<x:Root xmlns:x="a" x:attr="1" y:b="2">`).(xml.StartElement)
	after := roundtrip(t, before)
	read := xml.CopyToken(after)

	assert.True(t, startElementEquals(before, after))
	assert.Equal(t, read, after)
	assert.Equal(t, xml.StartElement{
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
	}, after)
}

func TestFixNamespacePrefixes(t *testing.T) {
	elements := []xml.StartElement{
		tokenize(t, `<Root>`).(xml.StartElement),
		tokenize(t, `<x:Root>`).(xml.StartElement),
		tokenize(t, `<x:Root xmlns:x="a" x:attr="1" y:b="2">`).(xml.StartElement),
		tokenize(t, `<Root a:x="1" b:y="2" a:z="3" c="4">`).(xml.StartElement),
		tokenize(t, `<Root xml:lang="en" xmlns:xmlns="v" _xmlns:a="1" xmlns:_xmlns="w">`).(xml.StartElement),
		tokenize(t, `<s:e xmlns:s="urn:s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">`).(xml.StartElement),
		// encoding/xml makes the prefix p of both namespaces, and then p_1 and p_2 as p is taken.
		{Name: xml.Name{Local: "Root"}, Attr: []xml.Attr{
			{Name: xml.Name{Space: "http://a/p", Local: "x"}, Value: "1"},
			{Name: xml.Name{Space: "http://b/p", Local: "y"}, Value: "2"},
			{Name: xml.Name{Space: "p", Local: "z"}, Value: "3"},
			{Name: xml.Name{Space: "p_1", Local: "w"}, Value: "4"},
		}},
	}

	for _, before := range elements {
		after := roundtrip(t, before)

		fixNamespacePrefixes(&before, &after)

		assert.Equal(t, before, after)
	}
}

// FuzzFixNamespacePrefixes checks that every start element encoding/xml reads is the same once it is written and
// read back and the xmlns attributes that were added for its prefixes are undone.
func FuzzFixNamespacePrefixes(f *testing.F) {
	f.Add(`<x:Root xmlns:x="a" x:attr="1" y:b="2">`)
	f.Add(`<a:e xmlns:a="u" xmlns:b="v" b:x="1" a:y="2" b:z="3" c="4" xmlns:_xmlns="w" _xmlns:q="5">`)
	f.Add(`<Root xml:lang="en" xmlns:xmlns="v" _xmlns:a="1" xmlns:_xmlns="w" p:x="1" p_1:y="2">`)

	f.Fuzz(func(t *testing.T, element string) {
		token, err := xml.NewDecoder(strings.NewReader(element)).RawToken()
		if err != nil {
			return
		}

		before, ok := xml.CopyToken(token).(xml.StartElement)
		if !ok {
			return
		}

		after, ok := tryRoundtrip(before)
		if !ok {
			return
		}

		if !startElementEquals(before, after) {
			t.Fatalf("%q is read back as %#v", element, after)
		}
	})
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
			assert.Equal(t, i == j, tokenEquals(token1, xml.CopyToken(token2)), "%T and %T", token1, token2)
		}
	}

	assert.False(t, tokenEquals(struct{}{}, struct{}{}), "a value that isn't a token never equals")
}

func TestErrorMessages(t *testing.T) {
	assert.Equal(t, "xmlrv: in token starting at 2:16: unexpected EOF",
		ValidationError{Start: 34, End: 54, Line: 2, Column: 16, err: io.ErrUnexpectedEOF}.Error())

	assert.Equal(t, "roundtrip error: expected {{ Foo} []}, observed {{ Bar} []}",
		RoundtripError{Expected: tokenize(t, `<Foo>`), Observed: tokenize(t, `<Bar>`)}.Error())
}

func tokenize(t *testing.T, s string) xml.Token {
	t.Helper()

	token, err := xml.NewDecoder(strings.NewReader(s)).RawToken()
	require.NoError(t, err)

	return xml.CopyToken(token)
}

// roundtrip returns the start element as encoding/xml reads it back once it has written it.
func roundtrip(t *testing.T, start xml.StartElement) xml.StartElement {
	t.Helper()

	after, ok := tryRoundtrip(start)
	require.True(t, ok)

	return after
}

func tryRoundtrip(start xml.StartElement) (xml.StartElement, bool) {
	var encoded strings.Builder

	encoder := xml.NewEncoder(&encoded)
	if encoder.EncodeToken(start) != nil || encoder.Flush() != nil {
		return xml.StartElement{}, false
	}

	token, err := xml.NewDecoder(strings.NewReader(encoded.String())).RawToken()
	if err != nil {
		return xml.StartElement{}, false
	}

	after, ok := xml.CopyToken(token).(xml.StartElement)

	return after, ok
}
