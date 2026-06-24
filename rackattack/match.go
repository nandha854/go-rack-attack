package rackattack

import (
	"path"
	"strings"
)

// matchPath reports whether reqPath matches pattern. An empty pattern matches
// everything. A pattern ending in "/*" matches the entire subtree (e.g.
// "/api/*" matches "/api", "/api/users", and "/api/v1/users"). Otherwise the
// pattern is treated as a glob per path.Match (so "*" matches within a single
// segment and patterns like "/api/v*/users" work), falling back to an exact
// comparison when the pattern contains no metacharacters.
func matchPath(pattern, reqPath string) bool {
	if pattern == "" {
		return true
	}
	clean := path.Clean(reqPath)

	// Subtree wildcard: "/prefix/*" matches the prefix and anything under it.
	if prefix, ok := strings.CutSuffix(pattern, "/*"); ok {
		if prefix == "" {
			return true // "/*" matches everything
		}
		return clean == prefix || strings.HasPrefix(clean, prefix+"/")
	}

	if strings.ContainsAny(pattern, "*?[") {
		if ok, err := path.Match(pattern, clean); err == nil && ok {
			return true
		}
		return false
	}

	return clean == path.Clean(pattern)
}

// matchMethod reports whether method matches the rule's method. An empty rule
// method matches everything. Comparison is case-insensitive.
func matchMethod(ruleMethod, method string) bool {
	if ruleMethod == "" {
		return true
	}
	return strings.EqualFold(ruleMethod, method)
}

// expandKey substitutes %{ip} and %{path} placeholders in a key template.
func expandKey(template, ip, reqPath string) string {
	if !strings.Contains(template, "%{") {
		return template
	}
	return strings.NewReplacer(
		"%{ip}", ip,
		"%{path}", reqPath,
	).Replace(template)
}
