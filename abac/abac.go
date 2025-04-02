package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Policy struct {
	Version   string         `json:"version"`
	Effect    string         `json:"effect"`
	Condition map[string]any `json:"condition"`
}

func evaluatePolicy(policy Policy, context map[string]any) (bool, [][]any) {
	results := make([][]any, 0)
	match := evaluateCondition(policy.Condition, context, &results)
	return match, results
}

func evaluateCondition(condition map[string]any, context map[string]any, results *[][]any) bool {
	for key, value := range condition {
		switch key {
		case "and":
			return evaluateAnd(value, context, results)
		case "or":

		case "not":
			subCondition, ok := value.(map[string]any)
			if !ok {
				return false
			}
			result := evaluateCondition(subCondition, context, results)
			return !result
		case "eq":
			comparisons, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for field, expectedValue := range comparisons {
				unInterpolated := expectedValue
				if isInterpolation(expectedValue) {
					expectedValue, ok = getContextValue(expectedValue.(string), context)
					if !ok {
						*results = append(*results, []any{false, field, unInterpolated, "eq", "undefined"})
						return false
					}
				}
				actualValue, exists := resolveField(context, field)
				if !exists {
					if results != nil {
						*results = append(*results, []any{false, field, actualValue, "eq", expectedValue})
					}
					return false
				}
				match := compareValues(actualValue, expectedValue)
				if *results != nil {
					*results = append(*results, []any{match, field, actualValue, "eq", expectedValue})
				}
				if !match {
					return false
				}
			}
			return true
		}
	}
	return false
}

func evaluateAnd(value any, context map[string]any, results *[][]any) bool {
	conditions, ok := value.([]any)
	if !ok {
		return false
	}
	for _, cond := range conditions {
		subCondition, ok := cond.(map[string]any)
		if !ok || !evaluateCondition(subCondition, context, results) {
			return false
		}
	}
	return true
}

func evaluateOr(value any, context map[string]any, results *[][]any) bool {
	conditions, ok := value.([]any)
	if !ok {
		return false
	}
	for _, cond := range conditions {
		subCondition, ok := cond.(map[string]any)
		if ok && evaluateCondition(subCondition, context, results) {
			return true
		}
	}
	return false
}

func compareValues[T comparable](actual, expected T) bool {
	return actual == expected
}

func isInterpolation(value any) bool {
	switch valueStr := value.(type) {
	case string:
		return strings.HasPrefix(valueStr, "{{") && strings.HasSuffix(valueStr, "}}")
	default:
		return false
	}
}

func getContextValue(field string, context map[string]any) (any, bool) {
	trimmedKey := strings.Trim(field, "{}")
	if resolvedValue, exists := resolveField(context, trimmedKey); exists {
		return resolvedValue, true
	}
	return nil, false
}

func resolveField(context map[string]any, field string) (any, bool) {
	if strings.Contains(field, "${") {
		field = strings.Trim(field, "${}")
	}
	value, exists := context[field]
	return value, exists
}

func main() {
	contextJSON := `{
		"user.role": "admin",
		"resource.location": "Canada",
		"user.location": "Canada",
		"resource.version": 1
	}`

	policyJSON := `{
		"version": "1.2.2",
		"effect": "allow",
		"condition": {
			"and": [
				{"eq": {"resource.location": "{{user.location}}"}},
				{"or": [
					{"eq": {"user.role": "admin"}},
					{"eq": {"user.role": "mod"}}
				]},
				{"eq": {"resource.location": "Canada"}},
				{"eq": {"resource.version": 1}},
				{"or": [
					{"and": [{"eq": {"resource.version": 1}}]},
					{"and": [
						{"eq": {"resource.version": 2}},
						{"eq": {"user.role": "admin"}}
					]}
				]}
			]
		}
	}`

	var policy Policy
	var context map[string]any

	json.Unmarshal([]byte(policyJSON), &policy)
	json.Unmarshal([]byte(contextJSON), &context)

	match, evaluations := evaluatePolicy(policy, context)
	fmt.Println("Policy Match:", match)
	fmt.Println("Evaluation Results:")
	for _, eval := range evaluations {
		fmt.Println(eval)
	}
}
