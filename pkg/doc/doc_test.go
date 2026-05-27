package doc

import "testing"

func TestGetPages(t *testing.T) {
	// Test German manual
	dePages := GetPages("de")
	if len(dePages) != 4 {
		t.Errorf("Expected 4 German pages, got %d", len(dePages))
	}
	if dePages[0].Title == "" {
		t.Errorf("Expected first German page to have a title")
	}

	// Test English manual
	enPages := GetPages("en")
	if len(enPages) != 4 {
		t.Errorf("Expected 4 English pages, got %d", len(enPages))
	}
	if enPages[0].Title == "" {
		t.Errorf("Expected first English page to have a title")
	}
}
