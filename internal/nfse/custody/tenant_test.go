package custody

import "testing"

func TestCompanyIDFor(t *testing.T) {
	got := CompanyIDFor("9f2c1a", "47.064.135/0001-84")
	if got != "9f2c1a_47064135000184" {
		t.Errorf("CompanyIDFor = %q", got)
	}
	if !validKeySegment(got) {
		t.Errorf("%q must be a valid Transit key segment", got)
	}
	if CompanyIDFor("t", "47064135000184") == CompanyIDFor("t", "11222333000181") {
		t.Error("different CNPJs of one tenant must not share a custody id")
	}
}
