package collection

import (
	"strings"
)

// AppendUniqueString appends the given string to the array if it does not already exist in the array and returns
// the new array.
func AppendUniqueString(arr []string, str string, ignoreCase bool) []string {
	for _, i := range arr {
		if ignoreCase {
			if strings.EqualFold(i, str) {
				return arr
			}
		} else {
			if i == str {
				return arr
			}
		}
	}
	return append(arr, str)
}
