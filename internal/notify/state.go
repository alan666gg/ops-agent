package notify

import "time"

type State struct {
	Key             string
	LastStatus      string
	LastFingerprint string
	LastNotifiedAt  time.Time
	LastChangedAt   time.Time
}

type Store interface {
	Get(key string) (State, bool, error)
	Put(state State) error
}

type MemoryStore struct {
	items map[string]State
}

func (m *MemoryStore) Get(key string) (State, bool, error) {
	if m.items == nil {
		m.items = map[string]State{}
	}
	st, ok := m.items[key]
	return st, ok, nil
}

func (m *MemoryStore) Put(state State) error {
	if m.items == nil {
		m.items = map[string]State{}
	}
	m.items[state.Key] = state
	return nil
}
