package k8s

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// dynamicResource stores information about dynamic Kubernetes resources.
type dynamicResource struct {
	obj *unstructured.Unstructured
	gvk *schema.GroupVersionKind
	dr  dynamic.ResourceInterface
}
