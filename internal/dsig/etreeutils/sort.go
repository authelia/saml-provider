package etreeutils

import (
	"cmp"
	"slices"

	"github.com/beevik/etree"
)

// SortAttrs sorts the attributes of an element into the order of XML C14N 1.0 section 2.2 and Exclusive XML C14N 1.0:
// the default namespace declaration, the other namespace declarations by prefix, and then the attributes by namespace
// URI, with the unqualified ones first, and then by local name. The namespace URI of a prefix is the one that
// namespace returns, which is the one in scope at the element, and an undeclared prefix is an
// ErrUndeclaredNSPrefix.
//
// The key of each attribute is found once before the attributes are sorted, so that the cost is in proportion to
// n log n for n attributes, as an element is canonicalized before its signature is verified.
func SortAttrs(attrs []etree.Attr, namespace func(prefix string) (string, error)) error {
	type keyed struct {
		attr etree.Attr

		// class is 0 for the default namespace declaration, 1 for another namespace declaration, and 2 for an
		// attribute.
		class int
		uri   string
		local string
	}

	sorted := make([]keyed, len(attrs))

	for i, attr := range attrs {
		k := keyed{attr: attr, local: attr.Key}

		switch {
		case attr.Space == defaultPrefix && attr.Key == xmlnsPrefix:
			k.class = 0
		case attr.Space == xmlnsPrefix:
			k.class = 1
		case attr.Space == defaultPrefix:
			k.class = 2
		default:
			uri, err := namespace(attr.Space)
			if err != nil {
				return err
			}

			k.class, k.uri = 2, uri
		}

		sorted[i] = k
	}

	slices.SortStableFunc(sorted, func(a, b keyed) int {
		return cmp.Or(cmp.Compare(a.class, b.class), cmp.Compare(a.uri, b.uri), cmp.Compare(a.local, b.local))
	})

	for i, k := range sorted {
		attrs[i] = k.attr
	}

	return nil
}

// SortAttrsCtx sorts the attributes of an element with the namespaces of ctx, which is the context of the element.
func SortAttrsCtx(ctx NSContext, attrs []etree.Attr) error {
	return SortAttrs(attrs, ctx.LookupPrefix)
}
