package adapter

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
)

func numericDate(value any) (*big.Rat, bool) {
	number, ok := value.(json.Number)
	if !ok || len(number) > 64 {
		return nil, false
	}
	text := number.String()
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		exponent, err := strconv.ParseInt(text[index+1:], 10, 32)
		if err != nil || exponent < -100 || exponent > 100 {
			return nil, false
		}
	}
	date, ok := new(big.Rat).SetString(text)
	if !ok || date.Cmp(big.NewRat(-253402300799, 1)) < 0 || date.Cmp(big.NewRat(253402300799, 1)) > 0 {
		return nil, false
	}
	return date, true
}

func audienceValues(value any) ([]string, bool) {
	if text, ok := value.(string); ok {
		return []string{text}, true
	}
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 128 {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func validateClaimTypes(claims map[string]any) string {
	for _, name := range []string{"iss", "sub", "jti"} {
		if value, exists := claims[name]; exists {
			if _, ok := value.(string); !ok {
				return "claims: expected string " + name
			}
		}
	}
	for _, name := range []string{"exp", "nbf", "iat"} {
		if value, exists := claims[name]; exists {
			if _, ok := numericDate(value); !ok {
				return "claims: invalid NumericDate " + name
			}
		}
	}
	if value, exists := claims["aud"]; exists {
		if _, ok := audienceValues(value); !ok {
			return "claims: invalid audience"
		}
	}
	return ""
}

func validateClaims(claims map[string]any, issuer, audience string, now, leeway int64, requireExpiration, checkIssuedAt bool) string {
	if err := validateClaimTypes(claims); err != "" {
		return err
	}
	if value, exists := claims["exp"]; exists {
		expires, _ := numericDate(value)
		if expires.Cmp(big.NewRat(now-leeway, 1)) <= 0 {
			return "expired: token has expired"
		}
	} else if requireExpiration {
		return "claims: expiration is required"
	}
	if value, exists := claims["nbf"]; exists {
		validAfter, _ := numericDate(value)
		if validAfter.Cmp(big.NewRat(now+leeway, 1)) > 0 {
			return "not_yet_valid: token not active"
		}
	}
	if value, exists := claims["iat"]; exists && checkIssuedAt {
		issued, _ := numericDate(value)
		if issued.Cmp(big.NewRat(now+leeway, 1)) > 0 {
			return "issued_at: token issued in future"
		}
	}
	if issuer != "" {
		actual, _ := claims["iss"].(string)
		if actual != issuer {
			return "issuer: issuer mismatch"
		}
	}
	if value, exists := claims["aud"]; exists {
		values, _ := audienceValues(value)
		matched := false
		for _, candidate := range values {
			if audience != "" && candidate == audience {
				matched = true
			}
		}
		if !matched {
			return "audience: audience mismatch or expected audience not configured"
		}
	} else if audience != "" {
		return "audience: audience is required"
	}
	return ""
}
