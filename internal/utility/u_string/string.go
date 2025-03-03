package u_string

import "unicode"

// ContainsDigitsAndLetters checks if a string contains both digits and letters
// which is a good heuristic for identifying date strings
func ContainsDigitsAndLetters(s string) bool {
	hasDigit := false
	hasLetter := false

	for _, r := range s {
		if unicode.IsDigit(r) {
			hasDigit = true
		} else if unicode.IsLetter(r) {
			hasLetter = true
		}

		if hasDigit && hasLetter {
			return true
		}
	}

	return false
}
