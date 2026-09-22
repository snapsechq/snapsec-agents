package cpulimit

// Apply imposes OS-specific CPU restrictions on the current process and its children.
// The target limit is approximately 20% of the system's total CPU capacity.
func Apply() error {
	return applyOSSpecific()
}
