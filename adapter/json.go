package adapter

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func unicodeJSON(input string) bool {
	if !utf8.ValidString(input) {
		return false
	}
	for i := 0; i < len(input); i++ {
		if input[i] != '"' {
			continue
		}
		i++
		for i < len(input) && input[i] != '"' {
			if input[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(input) {
				return false
			}
			if input[i] != 'u' {
				i++
				continue
			}
			if i+4 >= len(input) {
				return false
			}
			code, err := strconv.ParseUint(input[i+1:i+5], 16, 16)
			if err != nil {
				return false
			}
			i += 5
			if code >= 0xdc00 && code <= 0xdfff {
				return false
			}
			if code >= 0xd800 && code <= 0xdbff {
				if i+5 >= len(input) || input[i:i+2] != "\\u" {
					return false
				}
				low, err := strconv.ParseUint(input[i+2:i+6], 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

func jsonValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 64 || *nodes > 16384 {
		return nil, errors.New("JSON complexity limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := name.(string)
			if !ok {
				return nil, errors.New("invalid object member")
			}
			if _, exists := object[key]; exists {
				return nil, errors.New("duplicate JSON member")
			}
			value, err := jsonValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object end")
		}
		return object, nil
	case '[':
		values := []any{}
		for decoder.More() {
			value, err := jsonValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array end")
		}
		return values, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func strictObject(input string) (map[string]any, string) {
	if !unicodeJSON(input) {
		return nil, "json: invalid Unicode"
	}
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	nodes := 0
	value, err := jsonValue(decoder, 0, &nodes)
	if err != nil {
		return nil, "json: malformed, duplicate member or complexity limit"
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, "json: trailing data"
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, "json: expected object"
	}
	return object, ""
}
