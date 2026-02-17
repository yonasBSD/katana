package utils

import (
	"fmt"
	"testing"
)

func TestPathTrie_BasicInsertion(t *testing.T) {
	trie := NewPathTrie()
	segments := []string{"api", "v1", "users"}
	result := trie.Fingerprint("example.com", segments)

	for i, seg := range result {
		if seg != segments[i] {
			t.Errorf("segment %d = %q, want %q", i, seg, segments[i])
		}
	}
}

func TestPathTrie_RepeatedInsertionNoop(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"
	segments := []string{"api", "v1", "users"}

	// Inserting the same path many times should not trigger promotion
	for range 100 {
		result := trie.Fingerprint(host, segments)
		for i, seg := range result {
			if seg != segments[i] {
				t.Fatalf("repeated insertion changed segment %d: got %q, want %q", i, seg, segments[i])
			}
		}
	}
}

func TestPathTrie_PromotionExactThreshold(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	// Insert exactly threshold distinct children — should NOT promote
	for i := range DefaultPromotionThreshold {
		trie.Fingerprint(host, []string{"items", fmt.Sprintf("item-%d", i)})
	}
	result := trie.Fingerprint(host, []string{"items", "item-0"})
	if result[1] == "{param}" {
		t.Error("promoted at exactly threshold, should only promote when exceeding")
	}

	// One more distinct child triggers promotion
	result = trie.Fingerprint(host, []string{"items", "item-trigger"})
	if result[1] != "{param}" {
		t.Errorf("expected promotion after exceeding threshold, got %q", result[1])
	}
}

func TestPathTrie_Promotion(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint(host, []string{"blog", fmt.Sprintf("slug-%d", i)})
	}

	result := trie.Fingerprint(host, []string{"blog", "brand-new-slug"})
	if result[0] != "blog" {
		t.Errorf("static segment = %q, want %q", result[0], "blog")
	}
	if result[1] != "{param}" {
		t.Errorf("promoted segment = %q, want %q", result[1], "{param}")
	}
}

func TestPathTrie_PromotionDoesNotAffectOtherHosts(t *testing.T) {
	trie := NewPathTrie()

	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint("a.com", []string{"users", fmt.Sprintf("user-%d", i)})
	}

	result := trie.Fingerprint("b.com", []string{"users", "alice"})
	if result[1] != "alice" {
		t.Errorf("host isolation failed: got %q, want %q", result[1], "alice")
	}
}

func TestPathTrie_DeepPath(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint(host, []string{"api", "users", fmt.Sprintf("user-%d", i), "posts"})
	}

	result := trie.Fingerprint(host, []string{"api", "users", "new-user", "posts"})
	expected := []string{"api", "users", "{param}", "posts"}
	for i, seg := range result {
		if seg != expected[i] {
			t.Errorf("segment %d = %q, want %q", i, seg, expected[i])
		}
	}
}

func TestPathTrie_EmptySegments(t *testing.T) {
	trie := NewPathTrie()
	result := trie.Fingerprint("example.com", []string{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestPathTrie_SingleSegment(t *testing.T) {
	trie := NewPathTrie()

	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint("example.com", []string{fmt.Sprintf("page-%d", i)})
	}

	result := trie.Fingerprint("example.com", []string{"page-new"})
	if result[0] != "{param}" {
		t.Errorf("got %q, want {param}", result[0])
	}
}

func TestPathTrie_PromotedNodeChildrenNil(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint(host, []string{fmt.Sprintf("item-%d", i)})
	}

	root := trie.roots[host]
	if root.children != nil {
		t.Error("expected children to be nil after promotion")
	}
	if !root.promoted {
		t.Error("expected node to be promoted")
	}
}

func TestPathTrie_PreviousValueCollapseAfterPromotion(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	// Insert values before promotion
	trie.Fingerprint(host, []string{"blog", "first-post"})
	trie.Fingerprint(host, []string{"blog", "second-post"})

	// Trigger promotion
	for i := 2; i <= DefaultPromotionThreshold; i++ {
		trie.Fingerprint(host, []string{"blog", fmt.Sprintf("post-%d", i)})
	}

	// Previously seen "first-post" should now collapse
	result := trie.Fingerprint(host, []string{"blog", "first-post"})
	if result[1] != "{param}" {
		t.Errorf("previously seen value after promotion: got %q, want {param}", result[1])
	}
}

func TestPathTrie_SegmentsAfterPromotedNodeTrackedIndependently(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	// Promote the username segment: /users/{param}/...
	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint(host, []string{"users", fmt.Sprintf("user-%d", i), "profile"})
	}

	// After username is promoted, segments AFTER it should still track independently
	// Feed "profile" and "settings" — two distinct values, should not promote
	trie.Fingerprint(host, []string{"users", "someone", "settings"})
	result := trie.Fingerprint(host, []string{"users", "anyone", "settings"})

	if result[1] != "{param}" {
		t.Errorf("promoted segment: got %q, want {param}", result[1])
	}
	// "settings" should still be literal since paramChild only has 2 children
	if result[2] == "{param}" {
		t.Errorf("segment after promoted should not be promoted yet: got %q", result[2])
	}
}

func TestPathTrie_MultipleBranchesIndependent(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	// Promote /api/users/* but not /api/posts/*
	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint(host, []string{"api", "users", fmt.Sprintf("user-%d", i)})
	}
	// Only add a few posts
	trie.Fingerprint(host, []string{"api", "posts", "first"})
	trie.Fingerprint(host, []string{"api", "posts", "second"})

	// users should be promoted
	result := trie.Fingerprint(host, []string{"api", "users", "new"})
	if result[2] != "{param}" {
		t.Errorf("users branch should be promoted: got %q", result[2])
	}

	// posts should NOT be promoted
	result = trie.Fingerprint(host, []string{"api", "posts", "third"})
	if result[2] == "{param}" {
		t.Errorf("posts branch should not be promoted: got %q", result[2])
	}
}

func TestPathTrie_MultiplePromotionsAtDifferentDepths(t *testing.T) {
	trie := NewPathTrie()
	host := "example.com"

	// Promote at depth 0 (root children)
	for i := range DefaultPromotionThreshold + 1 {
		trie.Fingerprint(host, []string{fmt.Sprintf("section-%d", i), "page"})
	}

	result := trie.Fingerprint(host, []string{"section-new", "page"})
	if result[0] != "{param}" {
		t.Errorf("depth 0 promotion: got %q, want {param}", result[0])
	}

	// Depth 1 should still track normally through paramChild
	// "page" is the only value at depth 1 through paramChild, so not promoted
	if result[1] == "{param}" {
		t.Errorf("depth 1 should not be promoted yet: got %q", result[1])
	}
}

func TestPathTrie_NewHostLazyInit(t *testing.T) {
	trie := NewPathTrie()

	// Accessing new host should work without explicit init
	result := trie.Fingerprint("new-host.com", []string{"foo", "bar"})
	if result[0] != "foo" || result[1] != "bar" {
		t.Errorf("lazy init failed: got %v", result)
	}

	// Verify the host was created
	if _, exists := trie.roots["new-host.com"]; !exists {
		t.Error("host root not created after first access")
	}
}
