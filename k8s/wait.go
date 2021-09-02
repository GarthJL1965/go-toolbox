package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ConditionalWaiter stores information for executing a wait loop to ensure a specific condition is met for one
// or more resources.
type ConditionalWaiter struct {
	resource       *dynamicResource
	waitError      *error
	waitGroup      *sync.WaitGroup
	selectors      []string
	timeout        uint
	conditionName  string
	conditionValue string
}

// NewConditionalWaiter creates and initializes a new ConditionalWaiter object.
func NewConditionalWaiter(resource *dynamicResource, waitCondition WaitCondition, waitError *error,
	waitGroup *sync.WaitGroup) *ConditionalWaiter {

	w := &ConditionalWaiter{
		resource:       resource,
		waitError:      waitError,
		waitGroup:      waitGroup,
		timeout:        waitCondition.Timeout,
		selectors:      waitCondition.Selectors,
		conditionName:  waitCondition.Condition,
		conditionValue: "true",
	}
	if equalsIndex := strings.Index(w.conditionName, "="); equalsIndex != -1 {
		w.conditionName = waitCondition.Condition[0:equalsIndex]
		w.conditionValue = waitCondition.Condition[equalsIndex+1:]
	}
	return w
}

// Run executes a loop waiting for the given condition to be true for all matching resources.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func (w *ConditionalWaiter) Run(ctx context.Context) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().PackageCaller().
		Str("kind", w.resource.gvk.Kind).
		Str("group", w.resource.gvk.Group).
		Str("version", w.resource.gvk.Version).Logger()
	defer w.waitGroup.Done()

	// create a nice representation of the resource for messages
	var kind string
	if w.resource.gvk.Group != "" {
		kind = strings.ToLower(fmt.Sprintf("%s.%s", w.resource.gvk.Kind, w.resource.gvk.Group))
	} else {
		kind = strings.ToLower(fmt.Sprintf("%ss", w.resource.gvk.Kind))
	}

	// wait for objects
	objName := w.resource.obj.GetName()
	var subWaitGroup sync.WaitGroup
	if objName == "" {
		// lookup the resource based on selectors
		selectors := strings.Join(w.selectors, ",")
		var obj *unstructured.UnstructuredList
		var err error
		rounds := 0
		for { // wait up to 10 seconds for a resource to be created
			obj, err = w.resource.dr.List(context.Background(), metav1.ListOptions{
				LabelSelector: selectors,
			})
			if err != nil {
				logger.Error().Stack().Err(err).Str("label_selectors", selectors).
					Msgf("Failed to wait for %s resource matching '%s': %s", kind, selectors, err.Error())
				*w.waitError = err
				return
			}
			if len(obj.Items) > 0 {
				break
			}
			rounds++

			if rounds <= 5 {
				logger.Info().Msg("No matching resources found yet - retrying in 2 seconds...")
				time.Sleep(time.Millisecond * 2000)
			} else {
				err := fmt.Errorf("timed out waiting for resource(s) to be created")
				logger.Error().Stack().Err(err).Str("label_selectors", selectors).
					Msgf("Failed to wait for %s resource matching '%s': %s", kind, selectors, err.Error())
				*w.waitError = err
				return
			}
		}

		// add all matching resources to the list and wait for them
		for _, item := range obj.Items {
			subWaitGroup.Add(1)
			go w.waitForObject(item.GetName(), &subWaitGroup, ctx)
		}
	} else {
		subWaitGroup.Add(1)
		go w.waitForObject(objName, &subWaitGroup, ctx)
	}
	subWaitGroup.Wait()
}

// isConditionMet determines whether or not the condition has been met for the given object.
func (w *ConditionalWaiter) isConditionMet(obj *unstructured.Unstructured) (bool, error) {
	conditions, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	for _, conditionUncast := range conditions {
		condition := conditionUncast.(map[string]interface{})
		name, found, err := unstructured.NestedString(condition, "type")
		if !found || err != nil || !strings.EqualFold(name, w.conditionName) {
			continue
		}
		status, found, err := unstructured.NestedString(condition, "status")
		if !found || err != nil {
			continue
		}
		generation, found, _ := unstructured.NestedInt64(obj.Object, "metadata", "generation")
		if found {
			observedGeneration, found := getObservedGeneration(obj, condition)
			if found && observedGeneration < generation {
				return false, nil
			}
		}
		return strings.EqualFold(status, w.conditionValue), nil
	}
	return false, nil
}

// waitForObject waits for the condition to be true for the resource with the given name.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func (w *ConditionalWaiter) waitForObject(name string, wg *sync.WaitGroup, ctx context.Context) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().PackageCaller().
		Str("kind", w.resource.gvk.Kind).
		Str("group", w.resource.gvk.Group).
		Str("version", w.resource.gvk.Version).
		Str("name", name).
		Logger()
	defer wg.Done()
	kind := gvkToString(w.resource.gvk)
	logger.Info().Msgf("Waiting for %s resource: %s", kind, name)

	expires := time.Now().Add(time.Second * time.Duration(w.timeout))
	for {
		// lookup the object
		obj, err := w.resource.dr.Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			logger.Error().Stack().Err(err).
				Msgf("Failed to wait for %s resource named '%s': %s", kind, name, err.Error())
			*w.waitError = err
			return
		}

		// is the condition met
		isMet, err := w.isConditionMet(obj)
		if err != nil {
			logger.Error().Stack().Err(err).
				Msgf("Failed to wait for %s resource named '%s': %s", kind, name, err.Error())
			*w.waitError = err
			return
		}
		if isMet {
			logger.Info().Msgf("Finished waiting for %s resource: %s", kind, name)
			break
		}

		// has the wait timed out
		if time.Now().After(expires) {
			err := errors.New("timed out waiting for resource")
			logger.Error().Stack().Err(err).
				Msgf("Failed to wait for %s resource named '%s': %s", kind, name, err.Error())
			*w.waitError = err
			return
		}

		// wait for 1 second and try again
		logger.Debug().Msgf("Still waiting for %s resource: %s", kind, name)
		time.Sleep(time.Second)
	}
}

// getObservedGeneration returns the observedGeneration from the object.
func getObservedGeneration(obj *unstructured.Unstructured, condition map[string]interface{}) (int64, bool) {
	conditionObservedGeneration, found, _ := unstructured.NestedInt64(condition, "observedGeneration")
	if found {
		return conditionObservedGeneration, true
	}
	statusObservedGeneration, found, _ := unstructured.NestedInt64(obj.Object, "status", "observedGeneration")
	return statusObservedGeneration, found
}

// gvkToStirng converts a group/version/kind to a human-friendly string.
func gvkToString(gvk *schema.GroupVersionKind) string {
	if gvk.Group != "" {
		return strings.ToLower(fmt.Sprintf("%s.%s", gvk.Kind, gvk.Group))
	}
	return strings.ToLower(gvk.Kind)
}

// WaitCondition holds information on what resources we must wait on before continuing.
type WaitCondition struct {
	Condition   string                 `yaml:"condition"`
	RawResource map[string]interface{} `yaml:"resource"`
	Selectors   []string               `yaml:"selectors"`
	Timeout     uint                   `yaml:"timeout"`

	ResourceDefinition []byte
}
type marshalledWaitCondition WaitCondition

// UnmarshalYAML handles parsing YAML into an object and setting sensible defaults.
func (c *WaitCondition) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// parse the data
	var condition marshalledWaitCondition
	if err := unmarshal(&condition); err != nil {
		return err
	}

	// convert the raw resource data back into bytes that we can decode later
	res, err := yaml.Marshal(condition.RawResource)
	if err != nil {
		return err
	}
	condition.ResourceDefinition = res

	// make sure there is a non-empty condition
	if condition.Condition == "" {
		return fmt.Errorf("condition cannot be empty")
	}

	// validate condition values
	cond := strings.ToLower(condition.Condition)
	validConditions := map[string]int{
		"available":       1, // Deployment
		"available=true":  1,
		"available=false": 1,
		"ready":           1, // Pod
		"ready=true":      1,
		"ready=false":     1,
		"complete":        1, // Job
		"complete=true":   1,
		"complete=false":  1,
	}
	if _, ok := validConditions[cond]; !ok {
		return fmt.Errorf("'%s' is an unsupported condition", condition.Condition)
	}

	// copy values
	*c = WaitCondition(condition)
	return nil
}
