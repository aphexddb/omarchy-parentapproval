package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Parent struct {
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	PubKey    string    `json:"pubkey"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	PushReady bool      `json:"push_ready,omitempty"`
}

type Store struct {
	mu      sync.Mutex
	dir     string
	hostKey ed25519.PrivateKey
	parents map[string]Parent
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "parents"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, parents: map[string]Parent{}}
	if err := s.loadHostKey(); err != nil {
		return nil, err
	}
	if err := s.loadParents(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) HostPrivate() ed25519.PrivateKey { return s.hostKey }

func (s *Store) HostPublic() ed25519.PublicKey { return s.hostKey.Public().(ed25519.PublicKey) }

func (s *Store) loadHostKey() error {
	path := filepath.Join(s.dir, "host.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return errors.New("host.key is the wrong size")
		}
		s.hostKey = ed25519.PrivateKey(raw)
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return err
	}
	s.hostKey = priv
	return nil
}

func (s *Store) loadParents() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "parents"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, "parents", e.Name()))
		if err != nil {
			return err
		}
		var p Parent
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if p.DeviceID != "" {
			s.parents[p.DeviceID] = p
		}
	}
	return nil
}

func (s *Store) PutParent(p Parent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "parents", p.DeviceID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	s.parents[p.DeviceID] = p
	return nil
}

func (s *Store) GetParent(id string) (Parent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.parents[id]
	return p, ok
}

func (s *Store) TouchParent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.parents[id]
	if !ok {
		return
	}
	p.LastUsed = time.Now().UTC()
	s.writeParentLocked(p)
}

// SetPushReady marks that this phone completed /push/subscribe. Returns false
// if the parent is not stored yet.
func (s *Store) SetPushReady(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.parents[id]
	if !ok {
		return false
	}
	if p.PushReady {
		return true
	}
	p.PushReady = true
	s.writeParentLocked(p)
	return true
}

func (s *Store) PushReady(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.parents[id]
	return ok && p.PushReady
}

func (s *Store) writeParentLocked(p Parent) {
	s.parents[p.DeviceID] = p
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(s.dir, "parents", p.DeviceID+".json"), raw, 0o600)
}

func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.parents[id]; !ok {
		return os.ErrNotExist
	}
	delete(s.parents, id)
	return os.Remove(filepath.Join(s.dir, "parents", id+".json"))
}

func (s *Store) ListParents() []Parent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Parent, 0, len(s.parents))
	for _, p := range s.parents {
		out = append(out, p)
	}
	return out
}

func (s *Store) ParentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.parents)
}
