package cmd

// collectPages calls fetch(token) repeatedly, accumulating items until the
// returned nextToken is empty. fetch returns (items, nextToken, error).
func collectPages[T any](fetch func(token string) ([]T, string, error)) ([]T, error) {
	var all []T
	token := ""
	for {
		items, next, err := fetch(token)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == "" {
			return all, nil
		}
		token = next
	}
}
