// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certificatemanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"certificate-manager",
	"Provides TLS certificates and secrets",

	cell.Provide(NewManager),

	cell.Config(defaultManagerConfig),
)

type SecretManager interface {
	GetSecrets(ctx context.Context, secret *api.Secret, ns string) (string, map[string][]byte, error)
	GetSecretString(ctx context.Context, secret *api.Secret, ns string) (string, error)
}

var defaultManagerConfig = managerConfig{
	CertificatesDirectory: "/var/run/cilium/certs",
}

type managerConfig struct {
	// CertificatesDirectory is the root directory to be used by cilium to find
	// certificates locally.
	CertificatesDirectory string
}

func (mc managerConfig) Flags(flags *pflag.FlagSet) {
	flags.String("certificates-directory", mc.CertificatesDirectory, "Root directory to find certificates specified in L7 TLS policy enforcement")
}

// Manager will manage the way certificates are retrieved based in the given
// k8sClient and rootPath.
type manager struct {
	rootPath  string
	k8sClient k8sClient.Clientset
}

// NewManager returns a new manager.
func NewManager(cfg managerConfig, clientset k8sClient.Clientset) SecretManager {
	m := &manager{
		rootPath:  cfg.CertificatesDirectory,
		k8sClient: clientset,
	}

	return m
}

// GetSecrets returns either local or k8s secrets, giving precedence for local secrets if configured.
// The 'ns' parameter is used as the secret namespace if 'secret.Namespace' is an empty string.
func (m *manager) GetSecrets(ctx context.Context, secret *api.Secret, ns string) (string, map[string][]byte, error) {
	if secret == nil {
		return "", nil, fmt.Errorf("Secret must not be nil")
	}

	if secret.Namespace != "" {
		ns = secret.Namespace
	}

	if secret.Name == "" {
		return ns, nil, fmt.Errorf("Missing Secret name")
	}
	nsName := filepath.Join(ns, secret.Name)

	// Give priority to local secrets.
	// K8s API request is only done if the local secret directory can't be read!
	certPath := filepath.Join(m.rootPath, nsName)
	files, ioErr := os.ReadDir(certPath)
	if ioErr == nil {
		secrets := make(map[string][]byte, len(files))
		for _, file := range files {
			var bytes []byte

			path := filepath.Join(certPath, file.Name())
			bytes, ioErr = os.ReadFile(path)
			if ioErr == nil {
				secrets[file.Name()] = bytes
			}
		}
		// Return the (latest) error only if no secrets were found
		if len(secrets) == 0 && ioErr != nil {
			return nsName, nil, ioErr
		}
		return nsName, secrets, nil
	}
	secrets, err := m.k8sClient.GetSecrets(ctx, ns, secret.Name)
	return nsName, secrets, err
}

// GetSecretString returns a secret string stored in a k8s secret
func (m *manager) GetSecretString(ctx context.Context, secret *api.Secret, ns string) (string, error) {
	name, secrets, err := m.GetSecrets(ctx, secret, ns)
	if err != nil {
		return "", err
	}

	if len(secrets) == 1 {
		// get the lone item by looping into the map
		for _, value := range secrets {
			return string(value), nil
		}
	}
	return "", fmt.Errorf("Secret %s must have exactly one item", name)
}
