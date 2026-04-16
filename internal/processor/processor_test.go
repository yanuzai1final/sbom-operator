package processor

import (
	"testing"

	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/stretchr/testify/assert"
)

func TestInitTargets(t *testing.T) {
	internal.OperatorConfig = &internal.Config{
		Targets:       []string{"dtrack", "configmap"},
		DtrackBaseUrl: "http://localhost",
		DtrackApiKey:  "api",
	}

	targets := initTargets(nil)
	assert.Len(t, targets, 2)
}

func TestIsNamespaceAllowed(t *testing.T) {
	p := &Processor{
		allowedNamespaces: make(map[string]bool),
	}

	internal.OperatorConfig = &internal.Config{NamespaceLabelSelector: ""}
	assert.True(t, p.isNamespaceAllowed("default"))

	internal.OperatorConfig = &internal.Config{NamespaceLabelSelector: "scan=true"}
	assert.False(t, p.isNamespaceAllowed("default"))

	p.addAllowedNamespace("default")
	assert.True(t, p.isNamespaceAllowed("default"))

	p.removeAllowedNamespace("default")
	assert.False(t, p.isNamespaceAllowed("default"))
}

func TestNamespaceLabelMatches(t *testing.T) {
	p := &Processor{}
	selector := "scan=true"

	labels1 := map[string]string{"scan": "true"}
	assert.True(t, p.namespaceLabelMatches(labels1, selector))

	labels2 := map[string]string{"scan": "false"}
	assert.False(t, p.namespaceLabelMatches(labels2, selector))

	labels3 := map[string]string{"foo": "bar"}
	assert.False(t, p.namespaceLabelMatches(labels3, selector))
}

// TestExecuteSyftScansResetsImageMap ensures the per-pass image cache is
// cleared at the start of each executeSyftScans call. Without this, a failed
// upload from a previous pass (network hiccup, 401/413, syft resolve error)
// leaves a stale "true" entry that blocks retries on every subsequent pass
// until the operator restarts.
func TestExecuteSyftScansResetsImageMap(t *testing.T) {
	// Simulate a stale entry from a previous pass — an upload that failed
	// last tick and left a "true" entry in the cache.
	p := &Processor{
		imageMap: map[string]bool{"prev-tick-failed-image@sha256:abc": true},
		Targets:  []target.Target{}, // empty Targets → the LoadImages loop is a no-op
	}

	// Empty pods so scanPod is not exercised; we only verify the reset.
	p.executeSyftScans(nil, nil)

	_, exists := p.imageMap["prev-tick-failed-image@sha256:abc"]
	assert.False(t, exists, "stale imageMap entry from prior pass must be cleared")
	assert.Empty(t, p.imageMap, "imageMap must be empty when executeSyftScans runs with no pods")
}
