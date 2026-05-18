# attestation-service

Multi-vendor PKI aggregator. Collects mocked NVIDIA NVTrust, Intel TDX, and AMD
SEV-SNP quotes; validates them against vendor-CA mock chains; combines into an
RFC-0002 `AttestationReport`; signs with the aggregator key; returns the
report hash (which a real deployment would also submit to
`pallet-attestation-registry`).
