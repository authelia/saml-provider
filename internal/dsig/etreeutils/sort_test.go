package etreeutils

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// sortedElement returns the element of doc with its attributes sorted with its own context.
func sortedElement(t *testing.T, doc string) (string, error) {
	t.Helper()

	in := etree.NewDocument()
	require.NoError(t, in.ReadFromString(doc))

	el := in.Root().Copy()

	ctx, err := NewDefaultNSContext().SubContext(el)
	require.NoError(t, err)

	if err = SortAttrsCtx(ctx, el.Attr); err != nil {
		return "", err
	}

	out := etree.NewDocument()
	out.SetRoot(el)
	out.WriteSettings = etree.WriteSettings{CanonicalEndTags: true}

	return out.WriteToString()
}

func TestSortAttrs(t *testing.T) {
	testCases := map[string]struct {
		doc, expected string
	}{
		// Adapted from https://www.w3.org/TR/2001/REC-xml-c14n-20010315#Example-SETags
		"c14n example": {
			doc:      `<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I m" xmlns:b="http://www.ietf.org" xmlns:a="http://www.w3.org" xmlns="http://example.org"></e5>`,
			expected: `<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I m" attr2="all" b:attr="sorted" a:attr="out"></e5>`,
		},
		// Attributes are sorted by namespace URI before local name, whatever their prefixes are.
		"uri before local name": {
			doc:      `<e a:z="1" b:a="2" xmlns:b="urn:b" xmlns:a="urn:a" xml:lang="en"></e>`,
			expected: `<e xmlns:a="urn:a" xmlns:b="urn:b" xml:lang="en" a:z="1" b:a="2"></e>`,
		},
		// An attribute that is named as a prefix doesn't stand for its namespace.
		"attribute named as a prefix": {
			doc:      `<e a="urn:z" a:k="1" b:k="2" xmlns:a="urn:b" xmlns:b="urn:a"></e>`,
			expected: `<e xmlns:a="urn:b" xmlns:b="urn:a" a="urn:z" b:k="2" a:k="1"></e>`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := sortedElement(t, tc.doc)
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestSortAttrsUsesAncestorDeclarations(t *testing.T) {
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(`<r xmlns:a="urn:b" xmlns:b="urn:a"><e a:k="1" b:k="2"/></r>`))

	el := doc.Root().SelectElement("e")

	ctx, err := NSBuildParentContext(el)
	require.NoError(t, err)

	ctx, err = ctx.SubContext(el)
	require.NoError(t, err)

	require.NoError(t, SortAttrsCtx(ctx, el.Attr))
	require.Equal(t, []string{"b:k", "a:k"}, []string{el.Attr[0].FullKey(), el.Attr[1].FullKey()})
}

func TestSortAttrsUndeclaredPrefix(t *testing.T) {
	_, err := sortedElement(t, `<e a:k="1"></e>`)
	require.ErrorIs(t, err, ErrUndeclaredNSPrefix{Prefix: "a"})
}
