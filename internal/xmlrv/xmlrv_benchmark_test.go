package xmlrv

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// benchmarkSizes are the sizes of the documents, up to that of the largest request that is validated before it is
// authenticated, so that how the cost grows with the size shows.
var benchmarkSizes = []int{1 << 10, 2 << 10, 4 << 10, 8 << 10, 16 << 10}

// benchmarkDocuments are documents of size bytes at most, which are made of what may cost more to validate than
// its size: many tokens, many attributes, and the namespace prefixes that encoding/xml rewrites.
var benchmarkDocuments = []struct {
	name string
	make func(size int) string
}{
	{"text", func(size int) string {
		return benchmarkWrap(size, func(budget int) string { return strings.Repeat("x", budget) })
	}},
	{"escaped text", func(size int) string {
		return benchmarkWrap(size, func(budget int) string { return strings.Repeat(`"`, budget) })
	}},
	{"comments", func(size int) string {
		return benchmarkWrap(size, func(budget int) string { return strings.Repeat("<!---->", budget/len("<!---->")) })
	}},
	{"elements", func(size int) string {
		return benchmarkWrap(size, func(budget int) string { return strings.Repeat("<a/>", budget/len("<a/>")) })
	}},
	{"prefixed elements", func(size int) string {
		return benchmarkWrap(size, func(budget int) string { return strings.Repeat("<a:a/>", budget/len("<a:a/>")) })
	}},
	{"nested elements", func(size int) string {
		depth := size / len("<a></a>")

		return strings.Repeat("<a>", depth) + strings.Repeat("</a>", depth)
	}},
	{"elements with a prefixed attribute", func(size int) string {
		return benchmarkWrap(size, func(budget int) string {
			return strings.Repeat(`<a b:c=""/>`, budget/len(`<a b:c=""/>`))
		})
	}},
	{"attributes", func(size int) string {
		return benchmarkElement(size, func(i int) string { return " " + benchmarkName(i) + `=""` })
	}},
	{"namespace declarations", func(size int) string {
		return benchmarkElement(size, func(i int) string { return " xmlns:" + benchmarkName(i) + `=""` })
	}},
	{"attributes with one prefix", func(size int) string {
		return benchmarkElement(size, func(i int) string { return " a:" + benchmarkName(i) + `=""` })
	}},
	{"attributes with a prefix each", func(size int) string {
		return benchmarkElement(size, func(i int) string { return " " + benchmarkName(i) + `:a=""` })
	}},

	// An attribute with no value is the shortest there is. The parsers that read the document once it is
	// validated refuse it, but only after it is validated.
	{"attributes with a prefix each and no value", func(size int) string {
		return benchmarkElement(size, func(i int) string { return " " + benchmarkName(i) + ":a" })
	}},
}

// benchmarkWrap returns a root element with the content that fill returns for the bytes that are left.
func benchmarkWrap(size int, fill func(budget int) string) string {
	return "<r>" + fill(size-len("<r></r>")) + "</r>"
}

// benchmarkElement returns an element with the attributes attr(0), attr(1) and so on, for as many as fit.
func benchmarkElement(size int, attr func(i int) string) string {
	var b strings.Builder

	b.WriteString("<r")

	for i := 0; ; i++ {
		s := attr(i)
		if b.Len()+len(s)+len("/>") > size {
			break
		}

		b.WriteString(s)
	}

	b.WriteString("/>")

	return b.String()
}

// benchmarkName returns name i of a sequence of distinct XML names that are as short as they can be. The names
// have no x, so that none begins with xml.
func benchmarkName(i int) string {
	const letters = "abcdefghijklmnopqrstuvwyzABCDEFGHIJKLMNOPQRSTUVWYZ"

	name := []byte{}

	for i++; i > 0; i = (i - 1) / len(letters) {
		name = append(name, letters[(i-1)%len(letters)])
	}

	return string(name)
}

// benchmarkAuthnRequest is a signed request as a service provider makes it, to compare.
const benchmarkAuthnRequest = `<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-fcd102ff08c1a3f679d62a84116de12ca538be36" Version="2.0" IssueInstant="2026-11-18T12:16:29.11Z" Destination="https://idp.example.com/saml/sso" AssertionConsumerServiceURL="https://sp.example.com/saml2/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://sp.example.com/saml2/metadata</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id-fcd102ff08c1a3f679d62a84116de12ca538be36"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>aliciwqCjrLjgzj6I37RtzKldlwKtZw6Ia452hV2zVg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>` +
	"N2+sXRhGuNtSSysn0D1luMs6BNrR0rbj0gNjRN83f4Iy3gGuUicT2f8/XlEc4AMT4EpayPSh0QvIejgAhaDwILjDQkAYmOhDe68L7RC6jc9euouiNlaP7FP7K7EAvEARl3NIxxpuxpjgD7iqvBMa/nd/uvNvcS948QqwI4m4ZKBzTC4keO8/acGxLZHBAvldIhClweNrKcGZAHDH9wjr16DyEe2k9IcIdIC1mG7umPToXoh0VFGNuIa/PZNJi4o64o/aV/JerTEMMLsSDIew2K1V2hwLd5fUALRLLXUEPbZiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" +
	`</ds:SignatureValue></ds:Signature></samlp:AuthnRequest>`

// BenchmarkValidateAdversarial measures Validate on documents that are made to cost the most for their size.
func BenchmarkValidateAdversarial(b *testing.B) {
	for _, document := range benchmarkDocuments {
		for _, size := range benchmarkSizes {
			b.Run(fmt.Sprintf("%s/%dKiB", document.name, size>>10), func(b *testing.B) {
				data := []byte(document.make(size))

				require.LessOrEqual(b, len(data), size)

				benchmarkValidate(b, data)
			})
		}
	}
}

// BenchmarkValidateAuthnRequest measures Validate on a request as a service provider makes it.
func BenchmarkValidateAuthnRequest(b *testing.B) {
	benchmarkValidate(b, []byte(benchmarkAuthnRequest))
}

func benchmarkValidate(b *testing.B, data []byte) {
	b.Helper()

	require.NoError(b, Validate(data))

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		if err := Validate(data); err != nil {
			b.Fatal(err)
		}
	}
}
