// Package nfse is the NFS-e emission bounded context against the ADN / NFS-e
// Nacional (gov.br/nfse), for emitters in the Simples Nacional (MEI or ME/EPP).
// It is pure domain + application code: it assembles and signs the DPS
// (Declaração de Prestação de Serviços), then hands the signed document to a
// Transmitter port for mTLS delivery to the ADN.
//
// The package came from go-mei-das (internal/nfse), where it was proven
// against the ADN homologation; the gateway is now the single emitter that
// every product calls through POST /v1/nfse. Additions made here: the tomador
// (DPS toma), gateway-owned DPS numbering (Sequencer — several products emit
// for the same CNPJ), and keeping the authorised NFS-e XML.
//
// Hexagonal boundaries:
//   - The private key never crosses a boundary here. Signing is delegated to
//     the custody.FiscalSigner port: the domain computes the XMLDSIG
//     SignedInfo digest and receives a signature back. mTLS client
//     authentication is likewise the signer's tls.Certificate.
//   - Transport (REST/JSON + mTLS to the ADN) lives behind the Transmitter
//     port, implemented by internal/nfse/adn. The domain never imports
//     net/http, database/sql, or a vendor SDK.
//   - Persistence of an emission lives behind the Store port; the gateway
//     adapts it onto its own unit of work so an authorised emission and its
//     billing-ledger entry commit together (internal/app/nfse.go).
package nfse
