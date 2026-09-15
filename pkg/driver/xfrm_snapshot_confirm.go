package driver

// compatibleSnapshot reports whether a request snapshot matches a frozen kernel
// snapshot. The kernel resolves an omitted (zero) auth truncation length itself,
// so only that field may be filled from the frozen response; every explicit
// value, algorithm name, key hash and remaining field must match exactly.
func compatibleSnapshot(request, frozen stateSnapshot) bool {
	if request.auth.truncate == 0 {
		request.auth.truncate = frozen.auth.truncate
	}
	return request == frozen
}
