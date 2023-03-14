// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumnetworkpolicy

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/pkg/ingress/secrets"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

// event types
type ciliumNetworkPolicyAddedEvent struct {
	cnp *types.SlimCNP
}
type ciliumNetworkPolicyUpdatedEvent struct {
	oldCNP *types.SlimCNP
	newCNP *types.SlimCNP
}

type ciliumNetworkPolicyDeletedEvent struct {
	cnp *types.SlimCNP
}

// CNPWatcher is a simple pattern that allows to perform the following
// tasks:
//  1. Watch cilium network policy object with TLS rules
//  2. Manage synced TLS secrets in given namespace
//     - TLS secrets
type CNPWatcher struct {
	clientset k8sClient.Clientset

	cnpInformer cache.Controller
	cnpStore    cache.Store

	ccnpInformer cache.Controller
	ccnpStore    cache.Store

	secretManager secrets.SecretManager

	queue      workqueue.RateLimitingInterface
	maxRetries int

	enabledSecretsSync bool
	secretsNamespace   string

	log logrus.FieldLogger
}

type CNPWatcherOptions struct {
	SecretsNamespace string `mapstructure:"policy-secrets-namespace"`
	MaxRetries       int    `mapstructure:"policy-controller-max-retries"`
	Enabled          bool   `mapstructure:"enable-policy-secrets-sync"`
}

func (o CNPWatcherOptions) Flags(flags *pflag.FlagSet) {
	flags.StringVar(&o.SecretsNamespace, "policy-secrets-namespace", "cilium-secrets", "Namespace where TLS secrets are stored which are used in CNP rules")
	flags.IntVar(&o.MaxRetries, "policy-controller-max-retries", 10, "Maximum number of retries for a policy update in the controller")
	flags.BoolVar(&o.Enabled, "enable-policy-secrets-sync", false, "Enable policy secret sync watcher")
}

func newCNPWatcher(lc hive.Lifecycle, params CNPWatcherParams, opts CNPWatcherOptions) *CNPWatcher {
	if !opts.Enabled {
		params.Logger.Info("CNP secret sync is disabled")
		return nil
	}

	c := &CNPWatcher{
		clientset:        params.Clientset,
		queue:            workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		maxRetries:       opts.MaxRetries,
		secretsNamespace: opts.SecretsNamespace,
		log:              params.Logger,
	}

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {
				c.queue.Add(ciliumNetworkPolicyAddedEvent{cnp: cnp})
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldCNP := k8s.ObjToSlimCNP(oldObj)
			if oldCNP == nil {
				return
			}
			newCNP := k8s.ObjToSlimCNP(newObj)
			if newCNP == nil {
				return
			}
			c.queue.Add(ciliumNetworkPolicyUpdatedEvent{oldCNP: oldCNP, newCNP: newCNP})
		},
		DeleteFunc: func(obj interface{}) {
			if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {
				c.queue.Add(ciliumNetworkPolicyDeletedEvent{cnp: cnp})
			}
		},
	}

	c.cnpStore, c.cnpInformer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*ciliumv2.CiliumNetworkPolicyList](c.clientset.CiliumV2().CiliumNetworkPolicies(metav1.NamespaceAll)),
		&ciliumv2.CiliumNetworkPolicy{},
		0,
		handlers,
		k8s.ConvertToCNP,
	)

	c.ccnpStore, c.ccnpInformer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*ciliumv2.CiliumClusterwideNetworkPolicyList](c.clientset.CiliumV2().CiliumClusterwideNetworkPolicies()),
		&ciliumv2.CiliumClusterwideNetworkPolicy{},
		0,
		handlers,
		k8s.ConvertToCCNP,
	)

	lc.Append(hive.Hook{OnStart: c.onStart, OnStop: c.onStop})

	return c
}

func (c *CNPWatcher) onStart(ctx hive.HookContext) error {
	secretManager, err := secrets.NewSyncSecretsManager(c.clientset, c.secretsNamespace, c.maxRetries)
	if err != nil {
		return err
	}
	c.secretManager = secretManager

	go c.run()

	return nil
}

func (c *CNPWatcher) onStop(ctx hive.HookContext) error {
	c.queue.ShutDown()

	return nil
}

// Run kicks off the controlled loop
func (c *CNPWatcher) run() {
	defer c.queue.ShutDown()
	go c.cnpInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, c.cnpInformer.HasSynced) {
		return
	}

	go c.secretManager.Run()

	for c.processEvent() {
	}
}

func (c *CNPWatcher) processEvent() bool {
	event, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(event)
	err := c.handleEvent(event)
	if err == nil {
		c.queue.Forget(event)
	} else if c.queue.NumRequeues(event) < c.maxRetries {
		c.queue.AddRateLimited(event)
	} else {
		c.log.WithError(err).Errorf("Failed to process CNP event, skipping: %s", event)
		c.queue.Forget(event)
	}
	return true
}

func (c *CNPWatcher) handleCiliumNetworkPolicyAddedEvent(event ciliumNetworkPolicyAddedEvent) error {
	tlsContexts := c.getReferencedTLSContext(event.cnp)
	if len(tlsContexts) == 0 {
		// no secrets, no handling by us required
		return nil
	}

	c.secretManager.Add(secrets.CNPWithTLSAddedEvent{
		CNP:         event.cnp,
		TLSContexts: tlsContexts,
	})
	return nil
}

func (c *CNPWatcher) handleCiliumNetworkPolicyUpdatedEvent(event ciliumNetworkPolicyUpdatedEvent) error {

	oldTLSContexts := c.getReferencedTLSContext(event.oldCNP)
	newTLSContexts := c.getReferencedTLSContext(event.newCNP)

	if len(oldTLSContexts) == 0 && len(newTLSContexts) == 0 {
		// no secrets, no handling by us required
	}

	equal := true
	if len(oldTLSContexts) != len(newTLSContexts) {
		equal = false
	} else {
		for i := range oldTLSContexts {
			if !oldTLSContexts[i].DeepEqual(newTLSContexts[i]) {
				equal = false
				break
			}
		}
	}

	if !equal {
		c.secretManager.Add(secrets.CNPWithTLSUpdatedEvent{
			OldCNP:         event.oldCNP,
			NewCNP:         event.newCNP,
			OldTLSContexts: oldTLSContexts,
			NewTLSContexts: newTLSContexts,
		})
	}

	return nil
}

func (c *CNPWatcher) handleCiliumNetworkPolicyDeletedEvent(event ciliumNetworkPolicyDeletedEvent) error {
	tlsContexts := c.getReferencedTLSContext(event.cnp)
	if len(tlsContexts) == 0 {
		// no secrets, no handling by us required
		return nil
	}

	c.secretManager.Add(secrets.CNPWithTLSDeletedEvent{
		CNP:         event.cnp,
		TLSContexts: tlsContexts,
	})
	return nil
}

func (c *CNPWatcher) handleEvent(event interface{}) error {
	var err error
	switch ev := event.(type) {
	case ciliumNetworkPolicyAddedEvent:
		c.log.WithField(logfields.CiliumNetworkPolicyName, ev.cnp.Name).WithField(logfields.K8sNamespace, ev.cnp.Namespace).Debug("Handling CNP added event")
		err = c.handleCiliumNetworkPolicyAddedEvent(ev)
	case ciliumNetworkPolicyUpdatedEvent:
		c.log.WithField(logfields.CiliumNetworkPolicyName, ev.newCNP.Name).WithField(logfields.K8sNamespace, ev.newCNP.Namespace).Debug("Handling CNP updated event")
		err = c.handleCiliumNetworkPolicyUpdatedEvent(ev)
	case ciliumNetworkPolicyDeletedEvent:
		c.log.WithField(logfields.CiliumNetworkPolicyName, ev.cnp.Name).WithField(logfields.K8sNamespace, ev.cnp.Namespace).Debug("Handling CNP deleted event")
		err = c.handleCiliumNetworkPolicyDeletedEvent(ev)
	default:
		err = fmt.Errorf("received an unknown event: %t", ev)
	}
	return err
}

func (c *CNPWatcher) getReferencedTLSContext(pol *types.SlimCNP) []*api.TLSContext {
	var referencedTLS []*api.TLSContext

	for _, rule := range pol.Spec.Egress {
		for _, port := range rule.ToPorts {
			// only list if there is a secret referenced in the TLS context
			if port.OriginatingTLS != nil && port.OriginatingTLS.Secret != nil {
				referencedTLS = append(referencedTLS, port.OriginatingTLS)
			}

			if port.TerminatingTLS != nil && port.TerminatingTLS.Secret != nil {
				referencedTLS = append(referencedTLS, port.TerminatingTLS)
			}
		}
	}

	return referencedTLS
}
