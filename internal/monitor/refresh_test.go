package monitor

import "testing"

func TestDerivePanelLinkPrefersHTTPS(t *testing.T) {
	t.Parallel()

	link, source, ok := derivePanelLink(map[string]string{}, "router.local", []string{"80", "443"})
	if !ok {
		t.Fatal("expected panel link")
	}
	if link != "https://router.local" {
		t.Fatalf("got %q", link)
	}
	if source != "auto" {
		t.Fatalf("got source %q", source)
	}
}

func TestDerivePanelLinkKeepsManualValue(t *testing.T) {
	t.Parallel()

	link, source, ok := derivePanelLink(map[string]string{
		"panelLink":       "https://custom.local",
		"panelLinkSource": "manual",
	}, "router.local", []string{"443"})
	if ok || link != "" || source != "" {
		t.Fatalf("manual link should not be overwritten, got ok=%v link=%q source=%q", ok, link, source)
	}
}

func TestDerivePanelLinkClearsStaleAutoValue(t *testing.T) {
	t.Parallel()

	link, source, ok := derivePanelLink(map[string]string{
		"panelLink":       "https://old.local",
		"panelLinkSource": "auto",
	}, "router.local", nil)
	if !ok {
		t.Fatal("expected stale auto value to be cleared")
	}
	if link != "" || source != "" {
		t.Fatalf("expected clear signal, got link=%q source=%q", link, source)
	}
}
