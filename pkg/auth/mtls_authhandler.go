// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

type certificateProviderResult struct {
	cell.Out

	CertificateProvider certs.CertificateProvider `group:"certificateProviders"`
}

type mtlsParams struct {
	cell.In

	CertificateProviders []certs.CertificateProvider `group:"certificateProviders"`
}

func newMTLSAuthHandler(lc hive.Lifecycle, cfg MTLSConfig, params mtlsParams, log logrus.FieldLogger) authHandlerResult {
	if len(params.CertificateProviders) != 1 {
		log.Fatal("mTLS Auth Handler requires exactly one certificate provider")
		return authHandlerResult{}
	}
	mtls := &mtlsAuthHandler{
		cfg:  cfg,
		log:  log.WithField(logfields.LogSubsys, "mtls-auth-handler"),
		cert: params.CertificateProviders[0],
	}

	lc.Append(hive.Hook{OnStart: mtls.onStart, OnStop: mtls.onStop})

	return authHandlerResult{
		AuthHandler: mtls,
	}
}

type MTLSConfig struct {
	MTLSListenerPort int `mapstructure:"mtls-listener-port"`
}

func (cfg MTLSConfig) Flags(flags *pflag.FlagSet) {
	flags.IntVar(&cfg.MTLSListenerPort, "mtls-listener-port", 4434, "Port on which the CIlium Agent will perfom mTLS handshakes between agents on")
}

type mtlsAuthHandler struct {
	cell.In

	cfg MTLSConfig
	log logrus.FieldLogger

	cert certs.CertificateProvider
}

func (m *mtlsAuthHandler) authenticate(ar *authRequest) (*authResponse, error) {
	if ar == nil {
		return nil, errors.New("authRequest is nil")
	}
	cert, err := m.cert.GetCertificateForNumericIdentity(ar.localIdentity)
	if err != nil {
		return nil, fmt.Errorf("Failed to get certificate for identity %s: %w", ar.remoteIdentity.String(), err)
	}

	caBundle, err := m.cert.GetTrustBundle()
	if err != nil {
		return nil, fmt.Errorf("Failed to get CA bundle: %w", err)
	}

	// set up TCP connection
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ar.remoteHostIP.String(), m.cfg.MTLSListenerPort))
	if err != nil {
		return nil, fmt.Errorf("Failed to dial %s:%d: %w", ar.remoteHostIP.String(), m.cfg.MTLSListenerPort, err)
	}
	defer conn.Close()

	var expirationTime *time.Time

	// set up TLS socket
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: m.cert.NumericIdentityToSNI(ar.remoteIdentity),
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		},
		InsecureSkipVerify: true, // not insecure as we do the verification in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// verifiedChains will be nil as we set InsecureSkipVerify to true

			chain := make([]*x509.Certificate, 0, len(rawCerts))
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("Failed to parse certificate: %w", err)
				}
				chain = append(chain, cert)
			}

			expirationTime, err = m.verifyPeerCertificate(&ar.remoteIdentity, caBundle, [][]*x509.Certificate{chain})
			return err
		},
		ClientCAs: caBundle,
		RootCAs:   caBundle,
	})

	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("Failed to perform TLS handshake: %w", err)
	}

	if expirationTime == nil {
		return nil, errors.New("Failed to get expiration time of peer certificate")
	}

	m.log.WithField("remote-addr", tlsConn.RemoteAddr()).Info("mTLS handshake successful, go Cilium Service Mesh!")

	return &authResponse{
		expirationTime: *expirationTime,
	}, nil
}

func (m *mtlsAuthHandler) authType() policy.AuthType {
	return policy.AuthTypeMTLSSpiffe
}

func (m *mtlsAuthHandler) listenForConnections(ctx context.Context) error {
	// set up TCP listener

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", m.cfg.MTLSListenerPort))
	if err != nil {
		m.log.WithError(err).Fatal("Failed to start mTLS listener")
	}

	m.log.WithField(logfields.Port, m.cfg.MTLSListenerPort).Info("Started mTLS listener")

	for {
		conn, err := l.Accept()
		if err != nil {
			m.log.WithError(err).Error("Failed to accept connection")
			continue
		}
		go m.handleConnection(ctx, conn)
	}

}

func (m *mtlsAuthHandler) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	caBundle, err := m.cert.GetTrustBundle()
	if err != nil {
		m.log.WithError(err).Error("Failed to get CA bundle")
		return
	}
	// setup TLS socket
	tlsConn := tls.Server(conn, &tls.Config{
		ClientAuth:     tls.RequireAndVerifyClientCert,
		GetCertificate: m.GetCertificateForConnection,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			_, err := m.verifyPeerCertificate(nil, caBundle, verifiedChains)
			return err
		},
		ClientCAs: caBundle,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		m.log.WithError(err).Error("Failed to perform TLS handshake")
		return
	}

	// MAARTJE? Some thing else? Maybe saying hello? How unfriendly do we want our mTLS to be?
	// Terrible idea: send a random joke in case the other agent is having a bad day
}

func (m *mtlsAuthHandler) GetCertificateForConnection(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.log.WithField("SNI", info.ServerName).Debug("Got new TLS connection")
	id, err := m.cert.SNIToNumericIdentity(info.ServerName)
	if err != nil {
		return nil, fmt.Errorf("Failed to get identity for SNI %s: %w", info.ServerName, err)
	}

	return m.cert.GetCertificateForNumericIdentity(id)
}

func (m *mtlsAuthHandler) onStart(ctx hive.HookContext) error {
	m.log.Info("Starting mTLS auth handler")

	go m.listenForConnections(context.TODO())
	// go m.havingFun()
	return nil
}

func (m *mtlsAuthHandler) onStop(ctx hive.HookContext) error {
	m.log.Info("Stopping mTLS auth handler")
	return nil
}

func (m *mtlsAuthHandler) havingFun() {
	m.log.Info("Starting to do random mTLS handshakes for the lolz")

	for {
		time.Sleep(time.Second)
		// take two random IDs between 1 and 100
		fromID := 1 + rand.Intn(100)
		toID := 1 + rand.Intn(100)

		m.log.WithField("from", fromID).WithField("to", toID).Debug("Doing mTLS handshake")

		localhost := net.ParseIP("127.0.0.1")

		auth, err := m.authenticate(&authRequest{
			localIdentity:  identity.NumericIdentity(fromID),
			remoteIdentity: identity.NumericIdentity(toID),
			remoteHostIP:   localhost,
		})
		if err != nil || auth == nil {
			m.log.WithError(err).Error("Failed to authenticate()")
			continue
		}
		m.log.WithField("expiration", auth.expirationTime).Debug("mTLS handshake successful")
	}
}

// verifyPeerCertificate this is used for Go's TLS library to verify certificates
func (m *mtlsAuthHandler) verifyPeerCertificate(id *identity.NumericIdentity, caBundle *x509.CertPool, verifiedChains [][]*x509.Certificate) (*time.Time, error) {
	if len(verifiedChains) == 0 {
		return nil, errors.New("No verified chains found")
	}

	var expirationTime *time.Time

	for _, chain := range verifiedChains {
		opts := x509.VerifyOptions{
			Roots:         caBundle,
			Intermediates: x509.NewCertPool(),
		}

		var leaf *x509.Certificate
		for _, cert := range chain {
			if cert.IsCA {
				opts.Intermediates.AddCert(cert)
			} else {
				leaf = cert
			}
		}
		if leaf == nil {
			return nil, fmt.Errorf("No leaf certificate found")
		}
		if _, err := leaf.Verify(opts); err != nil {
			return nil, fmt.Errorf("Failed to verify certificate: %w", err)
		}

		if id != nil { // this will be empty in the peer connection
			m.log.WithField("SNI ID", id.String()).Debug("Validating Server SNI")
			if valid, err := m.cert.ValidateIdentity(*id, leaf); err != nil {
				return nil, fmt.Errorf("Failed to validate SAN: %w", err)
			} else if !valid {
				return nil, errors.New("Unable to validate SAN")
			}
		}

		expirationTime = &leaf.NotAfter

		m.log.WithField("uri-san", leaf.URIs).Debug("Validated certificate")
	}

	return expirationTime, nil
}
