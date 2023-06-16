// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// GRPCRouteInput is used to implement the Input interface for GRPCRoute
type GRPCRouteInput struct {
	Ctx       context.Context
	Logger    *logrus.Entry
	Client    client.Client
	Grants    *gatewayv1beta1.ReferenceGrantList
	GRPCRoute *gatewayv1alpha2.GRPCRoute

	gateways map[gatewayv1beta1.ParentReference]*gatewayv1beta1.Gateway
}

func (h *GRPCRouteInput) SetParentCondition(ref gatewayv1beta1.ParentReference, condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = h.GRPCRoute.GetGeneration()

	h.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})

}

func (h *GRPCRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = h.GRPCRoute.GetGeneration()

	for _, parent := range h.GRPCRoute.Spec.ParentRefs {
		h.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}

}

func (h *GRPCRouteInput) mergeStatusConditions(parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range h.GRPCRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		h.GRPCRoute.Status.RouteStatus.Parents[index].Conditions = merge(h.GRPCRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	h.GRPCRoute.Status.RouteStatus.Parents = append(h.GRPCRoute.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}

func (h *GRPCRouteInput) GetGrants() []gatewayv1beta1.ReferenceGrant {
	return h.Grants.Items
}

func (h *GRPCRouteInput) GetNamespace() string {
	return h.GRPCRoute.GetNamespace()
}

func (h *GRPCRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1beta1.SchemeGroupVersion.WithKind("GRPCRoute")
}

func (h *GRPCRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range h.GRPCRoute.Spec.Rules {
		rules = append(rules, &GRPCRouteRule{rule})
	}
	return rules
}

func (h *GRPCRouteInput) GetClient() client.Client {
	return h.Client
}

func (h *GRPCRouteInput) GetContext() context.Context {
	return h.Ctx
}

func (h *GRPCRouteInput) GetHostnames() []gatewayv1beta1.Hostname {
	return h.GRPCRoute.Spec.Hostnames
}

func (h *GRPCRouteInput) GetGateway(parent gatewayv1beta1.ParentReference) (*gatewayv1beta1.Gateway, error) {
	if h.gateways == nil {
		h.gateways = make(map[gatewayv1beta1.ParentReference]*gatewayv1beta1.Gateway)
	}

	if gw, exists := h.gateways[parent]; exists {
		return gw, nil
	}

	ns := helpers.NamespaceDerefOr(parent.Namespace, h.GetNamespace())
	gw := &gatewayv1beta1.Gateway{}

	if err := h.Client.Get(h.Ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			// if it is not just a not found error, we should return the error as something is bad
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}

		// Gateway does not exist skip further checks
		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}

	h.gateways[parent] = gw

	return gw, nil
}

func (h *GRPCRouteInput) Log() *logrus.Entry {
	return h.Logger
}

// GRPCRouteRule is used to implement the GenericRule interface for GRPCRoute
type GRPCRouteRule struct {
	Rule gatewayv1alpha2.GRPCRouteRule
}

func (t *GRPCRouteRule) GetBackendRefs() []gatewayv1beta1.BackendRef {
	refs := []gatewayv1beta1.BackendRef{}
	for _, backend := range t.Rule.BackendRefs {
		refs = append(refs, backend.BackendRef)
	}
	return refs
}
