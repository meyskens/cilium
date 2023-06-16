// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// grpcRouteReconciler reconciles a GRPCRoute object
type grpcRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel
}

// SetupWithManager sets up the controller with the Manager.
func (r *grpcRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.GRPCRoute{}, backendServiceIndex,
		func(rawObj client.Object) []string {
			hr, ok := rawObj.(*gatewayv1alpha2.GRPCRoute)
			if !ok {
				return nil
			}
			var backendServices []string
			for _, rule := range hr.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if !helpers.IsService(backend.BackendObjectReference) {
						continue
					}
					backendServices = append(backendServices,
						types.NamespacedName{
							Namespace: helpers.NamespaceDerefOr(backend.Namespace, hr.Namespace),
							Name:      string(backend.Name),
						}.String(),
					)
				}
			}
			return backendServices
		},
	); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.GRPCRoute{}, gatewayIndex,
		func(rawObj client.Object) []string {
			hr := rawObj.(*gatewayv1alpha2.GRPCRoute)
			var gateways []string
			for _, parent := range hr.Spec.ParentRefs {
				if !helpers.IsGateway(parent) {
					continue
				}
				gateways = append(gateways,
					types.NamespacedName{
						Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
						Name:      string(parent.Name),
					}.String(),
				)
			}
			return gateways
		},
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changes to GRPCRoute
		For(&gatewayv1alpha2.GRPCRoute{}).
		// Watch for changes to Backend services
		Watches(&source.Kind{Type: &corev1.Service{}}, r.enqueueRequestForBackendService()).
		// Watch for changes to Reference Grants
		Watches(&source.Kind{Type: &gatewayv1beta1.ReferenceGrant{}}, r.enqueueRequestForRequestGrant()).
		// Watch for changes to Gateways and enqueue GRPCRoutes that reference them,
		Watches(&source.Kind{Type: &gatewayv1beta1.Gateway{}}, r.enqueueRequestForGateway(),
			builder.WithPredicates(
				predicate.NewPredicateFuncs(hasMatchingController(context.Background(), mgr.GetClient(), controllerName)))).
		Complete(r)
}

// enqueueRequestForBackendService makes sure that GRPC Routes are reconciled
// if the backend services are updated.
func (r *grpcRouteReconciler) enqueueRequestForBackendService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(backendServiceIndex))
}

// enqueueRequestForRequestGrant makes sure that GRPC Routes in the same namespace are reconciled
func (r *grpcRouteReconciler) enqueueRequestForRequestGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueAll())
}

func (r *grpcRouteReconciler) enqueueRequestForGateway() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayIndex))
}

func (r *grpcRouteReconciler) enqueueFromIndex(index string) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "grpcRoute",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})
		grList := &gatewayv1alpha2.GRPCRouteList{}

		if err := r.Client.List(context.Background(), grList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.WithError(err).Error("Failed to get related GRPCRoutes")
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(grList.Items))
		for _, item := range grList.Items {
			route := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: route,
			})
			scopedLog.WithField("grpcRoute", route).Info("Enqueued GRPCRoute for resource")
		}
		return requests
	}
}

func (r *grpcRouteReconciler) enqueueAll() func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "grpcRoute",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})
		grList := &gatewayv1alpha2.GRPCRouteList{}

		if err := r.Client.List(context.Background(), grList, &client.ListOptions{}); err != nil {
			scopedLog.WithError(err).Error("Failed to get GRPCRoutes")
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(grList.Items))
		for _, item := range grList.Items {
			route := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: route,
			})
			scopedLog.WithField("grpcRoute", route).Info("Enqueued GRPCRoute for resource")
		}
		return requests
	}
}
