package version

import "testing"

func TestCurrentUsesInjectedVersion(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "v1.2.3"

	if got := Current().Version; got != "1.2.3" {
		t.Errorf("Current().Version = %q, want 1.2.3", got)
	}
}

func TestCurrentDefaultsToDev(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "dev"

	if got := Current().Version; got == "" {
		t.Error("Current().Version is empty, want dev or the module version")
	}
}
