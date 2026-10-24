package upstream

import (
	"encoding/json"
	"testing"
)

func schemaOf(t *testing.T, body string) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatal(err)
	}
	normalizeToolsSchema(obj)
	return obj
}

func TestNormalizeToolsSchemaTypeAliases(t *testing.T) {
	obj := schemaOf(t, `{"tools":[{"type":"function","function":{"name":"t1","parameters":{"type":"object","properties":{"a":{"type":"str"},"b":{"type":"int"},"c":{"type":"dict"}},"required":["a",null,""]}}}],"model":"m"}`)
	fn := obj["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
	params := fn["parameters"].(map[string]any)
	props := params["properties"].(map[string]any)
	if props["a"].(map[string]any)["type"] != "string" || props["b"].(map[string]any)["type"] != "integer" {
		t.Fatalf("python type aliases not mapped: %v", props)
	}
	c := props["c"].(map[string]any)
	if c["type"] != "object" {
		t.Fatalf("dict alias -> object failed: %v", c)
	}
	if _, has := c["properties"].(map[string]any); !has {
		t.Fatal("object without properties must gain an empty properties dict")
	}
	req, ok := params["required"].([]string)
	if !ok || len(req) != 1 || req[0] != "a" {
		t.Fatalf("required not cleaned to [\"a\"]: %v", params["required"])
	}
}

func TestNormalizeToolsSchemaNullMetadataAndTupleItems(t *testing.T) {
	obj := schemaOf(t, `{"tools":[{"type":"function","function":{"name":"t2","parameters":{"type":"object","properties":{"x":{"type":"array","items":[{"type":"string"},{"type":"integer"}],"description":null},"y":{"type":"weird"}},"$defs":{"D":{"type":"str"}}}}}]}`)
	params := obj["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)
	x := params["properties"].(map[string]any)["x"].(map[string]any)
	if _, has := x["description"]; has {
		t.Fatal("null description must be stripped")
	}
	items := x["items"].(map[string]any)
	if items["type"] != "string" {
		t.Fatalf("tuple items must unpack to first schema: %v", items)
	}
	y := params["properties"].(map[string]any)["y"].(map[string]any)
	if _, has := y["type"]; has {
		t.Fatalf("unknown type without structure must be dropped: %v", y)
	}
	defs := params["$defs"].(map[string]any)["D"].(map[string]any)
	if defs["type"] != "string" {
		t.Fatalf("$defs not recursively normalized: %v", defs)
	}
}

func TestNormalizeToolsSchemaBareToolWrapping(t *testing.T) {
	obj := schemaOf(t, `{"tools":[{"name":"bare","description":"d","parameters":{"type":"object"}}]}`)
	tool := obj["tools"].([]any)[0].(map[string]any)
	if tool["type"] != "function" {
		t.Fatalf("bare tool not wrapped: %v", tool)
	}
	fn := tool["function"].(map[string]any)
	if fn["name"] != "bare" {
		t.Fatalf("wrapped function lost name: %v", fn)
	}
}

func TestClassifyAccountRestricted(t *testing.T) {
	restricted := `{"code":11140,"msg":"account restricted due to unusual activity"}`
	if got := Classify(403, restricted); got != ErrAccountRestricted {
		t.Fatalf("restricted 11140 = %v, want ErrAccountRestricted", got)
	}
	cnForm := `{"code":11140,"msg":"request illegal"}`
	if got := Classify(403, cnForm); got != ErrAccountFault {
		t.Fatalf("request illegal 11140 = %v, want ErrAccountFault (existing behavior)", got)
	}
	if got := Classify(403, "账号存在异常行为，已限制使用"); got != ErrAccountRestricted {
		t.Fatalf("CN restricted marker = %v", got)
	}
}
