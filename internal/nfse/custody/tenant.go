package custody

// CompanyIDFor is the custody id of a certificate: the API tenant plus the
// holder CNPJ (digits). One tenant — e.g. an accounting platform reselling the
// API — serves many MEIs, each with its own A1, so the tenant alone cannot key
// the custody (nfse_a1_certs keeps one certificate per company_id).
//
// The "_" separator stays inside the Transit key-segment charset, and the CNPJ
// is always the trailing 14 digits, so (tenant, cnpj) → id stays injective.
func CompanyIDFor(tenantID, cnpj string) string {
	return tenantID + "_" + onlyDigits(cnpj)
}
