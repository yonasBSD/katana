package utils

// DefaultPromotionThreshold is the number of distinct children a trie node
// must accumulate before being promoted to a parameter node.
const DefaultPromotionThreshold = 10

// PathTrie is a per-host adaptive trie that tracks unique path segments
// at each position. When a node accumulates more distinct children than
// the promotion threshold, it is promoted to a parameter node and all
// future values at that position are collapsed.
type PathTrie struct {
	roots     map[string]*trieNode
	threshold int
}

type trieNode struct {
	children   map[string]*trieNode
	paramChild *trieNode
	promoted   bool
}

// NewPathTrie creates a new PathTrie with the default promotion threshold.
func NewPathTrie() *PathTrie {
	return &PathTrie{
		roots:     make(map[string]*trieNode),
		threshold: DefaultPromotionThreshold,
	}
}

// Fingerprint walks the trie for the given host and segments, returning
// a new slice where promoted positions are replaced with "{param}".
// Non-promoted segments are registered in the trie for future cardinality tracking.
func (t *PathTrie) Fingerprint(host string, segments []string) []string {
	root, ok := t.roots[host]
	if !ok {
		root = &trieNode{children: make(map[string]*trieNode)}
		t.roots[host] = root
	}

	result := make([]string, len(segments))
	current := root

	for i, seg := range segments {
		if current.promoted {
			result[i] = "{param}"
			if current.paramChild == nil {
				current.paramChild = &trieNode{children: make(map[string]*trieNode)}
			}
			current = current.paramChild
			continue
		}

		child, exists := current.children[seg]
		if !exists {
			child = &trieNode{children: make(map[string]*trieNode)}
			current.children[seg] = child

			if len(current.children) > t.threshold {
				current.promoted = true
				current.paramChild = &trieNode{children: make(map[string]*trieNode)}
				current.children = nil
				result[i] = "{param}"
				current = current.paramChild
				continue
			}
		}

		result[i] = seg
		current = child
	}

	return result
}
