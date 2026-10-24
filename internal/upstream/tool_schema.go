// tool_schema.go 工具函数 JSON Schema 深度规整（根除上游 400 code 11129）。
//
// 复杂 Agent（Hermes Agent 等）的工具声明里会出现：Python 风格类型别名
//（str/int/bool/dict/list）、值为 null 的元数据字段（description/title/format/
// pattern）、Tuple 形态的 array items、缺 type='function' 包装的根级工具、
// 非字符串 required 等——上游 Go validator 强类型反序列化会整段拒收
//（400 code 11129 invalid_function_call_*）。本文件在出站前递归规整：
//   1. 剔除值为 null 的元数据键（description/title/format/pattern/items/default）；
//   2. 类型别名映射到标准 JSON Schema 类型；未知类型按结构特征回退
//      （有 properties → object，有 items → array，否则删 type）；
//   3. object 形态恒带 properties 字典；required 清洗为非空字符串列表；
//   4. array items：列表形态（Tuple）解包取首个结构；null 剔除；
//   5. 递归处理 properties / $defs / definitions / anyOf / oneOf / allOf；
//   6. 根级 tools 条目缺 type='function' 但有 name → 自动包一层 function 包装。
//
// 形态依据 Hub 3307d77（实测 Hermes Agent 触发 11129 的根因定位），Go 移植。
// 与 sanitize 开关无关：这是「让请求通过」的安全网（同 tool 配对三步的定位），
// 规整只做无害化改写，不改变语义。
package upstream

// schemaTypeAliases Python/非标类型别名 → 标准 JSON Schema 类型。
var schemaTypeAliases = map[string]string{
	"str":   "string",
	"text":  "string",
	"int":   "integer",
	"bool":  "boolean",
	"dict":  "object",
	"list":  "array",
	"float": "number",
}

// schemaNullStripKeys 值为 null 时剔除的元数据键（上游强类型拒绝 null 值）。
var schemaNullStripKeys = []string{"description", "title", "format", "pattern", "items", "default"}

// normalizeToolsSchema 规整请求体的 tools / functions 声明。无 tools 或形态
// 已合规时零改动。单 pass、就地修改 obj。
func normalizeToolsSchema(obj map[string]any) {
	if raw, ok := obj["tools"].([]any); ok && len(raw) > 0 {
		for i, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			// 根级缺 type 包装但直呼工具字段（name/description/parameters 平铺）
			// → 包一层官方 {type:function, function:{...}} 形态。
			if t, _ := m["type"].(string); t != "function" {
				if _, hasName := m["name"]; hasName {
					if _, hasFn := m["function"]; !hasFn {
						wrapped := make(map[string]any, len(m))
						for k, v := range m {
							wrapped[k] = v
						}
						raw[i] = map[string]any{"type": "function", "function": wrapped}
						m = raw[i].(map[string]any)
					}
				}
			}
			if fn, ok := m["function"].(map[string]any); ok {
				if params, ok := fn["parameters"].(map[string]any); ok {
					deepNormalizeSchema(params)
				}
			}
		}
	}
	// 旧版 functions 字段（OpenAI 已废弃但部分客户端仍发）：parameters 同样规整。
	if raw, ok := obj["functions"].([]any); ok && len(raw) > 0 {
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if params, ok := m["parameters"].(map[string]any); ok {
				deepNormalizeSchema(params)
			}
		}
	}
}

// deepNormalizeSchema 递归规整一个 JSON Schema 节点（就地修改）。
func deepNormalizeSchema(s map[string]any) {
	// 1. null 值元数据键剔除。
	for _, k := range schemaNullStripKeys {
		if v, ok := s[k]; ok && v == nil {
			delete(s, k)
		}
	}
	// 2. 类型声明归一。
	switch typ := s["type"].(type) {
	case string:
		normalized := normalizeSchemaTypeString(typ, s)
		if normalized == "" {
			delete(s, "type")
		} else {
			s["type"] = normalized
		}
	case []any:
		var out []string
		for _, t := range typ {
			ts, ok := t.(string)
			if !ok || ts == "" {
				continue
			}
			if mapped, ok := schemaTypeAliases[ts]; ok {
				ts = mapped
			}
			out = append(out, ts)
		}
		if len(out) > 0 {
			s["type"] = out
		} else {
			delete(s, "type")
		}
	case nil:
		// 无 type：结构特征补齐（properties → object）。
		if _, hasProps := s["properties"]; hasProps {
			s["type"] = "object"
		}
	}
	// 3. object 恒带 properties 字典。
	if t, _ := s["type"].(string); t == "object" {
		if props, ok := s["properties"].(map[string]any); !ok || props == nil {
			s["properties"] = map[string]any{}
		}
	}
	// 4. required 清洗：null/空串剔除；字符串提升为列表；空列表剔除。
	if req, ok := s["required"]; ok {
		switch v := req.(type) {
		case []any:
			var cleaned []string
			for _, item := range v {
				if ts, ok := item.(string); ok && ts != "" {
					cleaned = append(cleaned, ts)
				}
			}
			if len(cleaned) > 0 {
				s["required"] = cleaned
			} else {
				delete(s, "required")
			}
		case string:
			if v != "" {
				s["required"] = []string{v}
			} else {
				delete(s, "required")
			}
		default:
			delete(s, "required")
		}
	}
	// 5. array items：Tuple 列表解包取首个结构；dict 递归；null 已被 1 剔除。
	switch items := s["items"].(type) {
	case []any:
		var first map[string]any
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				first = m
				break
			}
		}
		if first != nil {
			cp := make(map[string]any, len(first))
			for k, v := range first {
				cp[k] = v
			}
			deepNormalizeSchema(cp)
			s["items"] = cp
		} else {
			s["items"] = map[string]any{"type": "string"}
		}
	case map[string]any:
		deepNormalizeSchema(items)
	}
	// 6-8. 递归 properties / $defs / definitions / 组合关键字。
	if props, ok := s["properties"].(map[string]any); ok {
		for _, v := range props {
			if m, ok := v.(map[string]any); ok {
				deepNormalizeSchema(m)
			}
		}
	}
	for _, defKey := range []string{"$defs", "definitions"} {
		if defs, ok := s[defKey].(map[string]any); ok {
			for _, v := range defs {
				if m, ok := v.(map[string]any); ok {
					deepNormalizeSchema(m)
				}
			}
		}
	}
	for _, combKey := range []string{"anyOf", "oneOf", "allOf"} {
		if subs, ok := s[combKey].([]any); ok {
			for _, v := range subs {
				if m, ok := v.(map[string]any); ok {
					deepNormalizeSchema(m)
				}
			}
		}
	}
}

// normalizeSchemaTypeString 单个类型字符串归一：别名映射 / 小写化 / 未知类型按
// 结构回退（返回 "" 表示应删掉 type 键）。
func normalizeSchemaTypeString(typ string, s map[string]any) string {
	t := typ
	if mapped, ok := schemaTypeAliases[t]; ok {
		t = mapped
	}
	switch t {
	case "string", "number", "integer", "boolean", "array", "object", "null":
		return t
	}
	// 非标准类型：按结构特征回退。
	if _, hasProps := s["properties"]; hasProps {
		return "object"
	}
	if _, hasItems := s["items"]; hasItems {
		return "array"
	}
	return ""
}
