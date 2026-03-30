package canonicaljson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

func Marshal(v any) ([]byte, error) {
	var normalized any
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, fmt.Errorf("unmarshal normalized: %w", err)
	}
	buf := bytes.Buffer{}
	if err := writeCanonical(&buf, normalized); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		j, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(j)
	case string:
		j, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(j)
	case []any:
		buf.WriteByte('[')
		for i, it := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, it); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ks, _ := json.Marshal(k)
			buf.Write(ks)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical type %T", v)
	}
	return nil
}
