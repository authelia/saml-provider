package etreeutils

import (
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// nestedElement builds the tree directly rather than parsing it, so that the
// depth under test stays independent of etree's ReadSettings.MaxDepth.
func nestedElement(t *testing.T, depth int) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")

	el := root
	for i := 0; i < depth; i++ {
		el = el.CreateElement("a")
	}

	return root
}

func TestNSDetatchLimit(t *testing.T) {
	detached, err := NSDetatch(NewDefaultNSContext(), nestedElement(t, 10))
	require.NoError(t, err)
	require.NotNil(t, detached)

	_, err = NSDetatch(NewDefaultNSContext(), nestedElement(t, 5000))
	require.ErrorIs(t, err, ErrTraversalLimit)
}

// declaring returns an element named tag that declares the namespace prefixes p0, p1 and so on, up to count of them.
func declaring(tag string, count int) *etree.Element {
	el := etree.NewElement(tag)

	for i := range count {
		el.CreateAttr(fmt.Sprintf("xmlns:p%d", i), "urn:p")
	}

	return el
}

func TestSubContextSharesContextOfElementWithoutDeclarations(t *testing.T) {
	ctx, err := NewDefaultNSContext().SubContext(declaring("root", 2))
	require.NoError(t, err)

	el := etree.NewElement("a")
	el.CreateAttr("p0:attr", "value")

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := ctx.SubContext(el); err != nil {
			t.Fatal(err)
		}
	})

	require.Zero(t, allocs)
}

func TestSubContextLimitsPrefixesInScope(t *testing.T) {
	// The default context has the default namespace and the xml and xmlns prefixes in scope.
	builtin := len(NewDefaultNSContext().prefixes)

	ctx, err := NewDefaultNSContext().SubContext(declaring("root", MaxPrefixes-builtin))
	require.NoError(t, err)
	require.Len(t, ctx.prefixes, MaxPrefixes)

	_, err = NewDefaultNSContext().SubContext(declaring("root", MaxPrefixes-builtin+1))
	require.ErrorIs(t, err, ErrTooManyPrefixes)

	// The prefixes that ancestors declare count too, and declaring one again with another namespace adds none.
	child := etree.NewElement("a")
	child.CreateAttr("xmlns:p0", "urn:other")

	sub, err := ctx.SubContext(child)
	require.NoError(t, err)
	require.Equal(t, "urn:other", sub.prefixes["p0"])
	require.Equal(t, "urn:p", ctx.prefixes["p0"])

	child.CreateAttr("xmlns:extra", "urn:extra")

	_, err = ctx.SubContext(child)
	require.ErrorIs(t, err, ErrTooManyPrefixes)
}

func TestNSTraverseKeepsDeclarationsToTheirElement(t *testing.T) {
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(`<root xmlns:a="urn:root"><one xmlns:a="urn:one" xmlns:b="urn:b"><a:x/></one><two><a:x/></two></root>`))

	var namespaces []string

	err := NSFindIterate(doc.Root(), "urn:root", "x", func(ctx NSContext, el *etree.Element) error {
		_, err := ctx.LookupPrefix("b")
		namespaces = append(namespaces, el.Parent().Tag+" "+fmt.Sprint(err != nil))

		return nil
	})
	require.NoError(t, err)

	// Only the x in two is in urn:root, and b, which one declares, is not in scope there.
	require.Equal(t, []string{"two true"}, namespaces)
}

func TestTransformExcC14nKeepsDeclarationsToTheirElement(t *testing.T) {
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(`<root xmlns:a="urn:a"><one xmlns:b="urn:b"><a:x b:y="1"/></one><two><a:x/></two><a:three/></root>`))

	require.NoError(t, TransformExcC14n(doc.Root(), "", false))

	out, err := doc.WriteToString()
	require.NoError(t, err)

	// Each element declares what it uses that no ancestor in the output declared, and siblings declare it again.
	require.Equal(t, `<root><one><a:x xmlns:a="urn:a" xmlns:b="urn:b" b:y="1"/></one><two><a:x xmlns:a="urn:a"/></two><a:three xmlns:a="urn:a"/></root>`, out)
}
