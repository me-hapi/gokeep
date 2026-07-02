package main

import "sort"

// shortUID returns the first 8 chars of a UID.
func shortUID(uid string) string {
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}

// sortedKeysByName returns the keys of m sorted by the result of nameFn.
func sortedKeysByName[K comparable, V any](m map[K]V, nameFn func(V) string) []K {
	type kv struct {
		key  K
		name string
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{key: k, name: nameFn(v)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	keys := make([]K, len(items))
	for i, item := range items {
		keys[i] = item.key
	}
	return keys
}
