package pool

// MaxPriority 是面板支持的最高调度优先级；缺省为 0。
const MaxPriority = 100

// SetPriority 只修改调度偏好，不触碰冷却、用量、凭证或会话绑定。
// 返回 false 表示账号不存在或优先级越界。
func (p *Pool) SetPriority(uid string, priority int) bool {
	if priority < 0 || priority > MaxPriority {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	if e.priority != priority {
		e.priority = priority
		p.dirty.Store(true)
	}
	return true
}

// PreferNew 从已过滤可用性的会话候选中保留最高优先级，保持原顺序和虚拟实例。
// 不修改输入，也不用于已有绑定的健康校验。
func (p *Pool) PreferNew(uids []string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	best := -1
	out := make([]string, 0, len(uids))
	for _, uid := range uids {
		e, ok := p.byUID[uid]
		if !ok || e.priority < best {
			continue
		}
		if e.priority > best {
			best = e.priority
			out = out[:0]
		}
		out = append(out, uid)
	}
	return out
}
