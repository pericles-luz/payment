-- Reverses 0020. Emission records, cached XML/PDF, certificate metadata and the
-- DPS numbering are discarded; the authorised NFS-e themselves remain at the ADN.
-- The A1 private keys in Vault transit are NOT touched (shred them explicitly).

DROP TABLE IF EXISTS nfse_dps_sequences;
DROP TABLE IF EXISTS nfse_a1_certs;
DROP TABLE IF EXISTS nfse_emissions;
