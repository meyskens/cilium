package certs

import (
	"crypto/tls"
	"crypto/x509"
)

type CertificateProvider interface {
	// GetTrustBundle gives the CA trust bundle for the certificate provider
	// this is then used to verify the certificates given by the peer in the handshake
	GetTrustBundle() (*x509.CertPool, error)

	// GetCertificateForIdentity gives the certificate and intermediates required
	// to send as trust chain for a certain identity as well as a private key
	GetCertificateForIdentity(identity string) (*tls.Certificate, error)

	// ValidateSAN will check if the SANs are valid for the given identity
	// this function is needed as SPIFFE encodes the full ID in the URI SAN
	ValidateSAN(identity string, cert *x509.Certificate) (bool, error)
}
