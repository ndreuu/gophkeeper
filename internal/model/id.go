package model

// ValidID reports whether id contains exactly 32 lowercase hexadecimal characters.
func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}
