package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrNotFound = errors.New("secret not found")
	ErrConsumed = errors.New("secret already consumed")
	ErrExpired  = errors.New("secret expired")
	ErrLocked   = errors.New("too many failed attempts")
)

var bucket = []byte("secrets")

type Secret struct {
	ID          string     `json:"id"`
	Ciphertext  []byte     `json:"ct"`
	IV          []byte     `json:"iv"`
	Question    string     `json:"q,omitempty"`
	AnswerHash  []byte     `json:"ah,omitempty"`
	MaxAttempts int        `json:"ma"`
	Attempts    int        `json:"at"`
	ExpiresAt   time.Time  `json:"exp"`
	ConsumedAt  *time.Time `json:"cat,omitempty"`
	UnlockedAt  *time.Time `json:"uat,omitempty"`
	CreatedAt   time.Time  `json:"ct_at"`
}

type Store struct {
	db    *bolt.DB
	count atomic.Int64
}

func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	err = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(bucket)
		if e != nil {
			return e
		}
		// Seed the in-memory counter from the actual key count once at open.
		// Subsequent writes update it via tx.OnCommit hooks, so we never have
		// to walk the bucket again on the request path.
		s.count.Store(int64(b.Stats().KeyN))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Count() int64 { return s.count.Load() }

var ErrCapacity = errors.New("at capacity")

func (s *Store) Put(sec *Secret) error {
	return s.PutIfUnder(sec, 0)
}

func (s *Store) PutIfUnder(sec *Secret, maxKeys int) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if maxKeys > 0 && s.count.Load() >= int64(maxKeys) {
			return ErrCapacity
		}
		existed := b.Get([]byte(sec.ID)) != nil
		data, err := json.Marshal(sec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(sec.ID), data); err != nil {
			return err
		}
		if !existed {
			tx.OnCommit(func() { s.count.Add(1) })
		}
		return nil
	})
}

func (s *Store) Get(id string) (*Secret, error) {
	var sec Secret
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &sec)
	})
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

func (s *Store) Delete(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b.Get([]byte(id)) == nil {
			return nil
		}
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
		tx.OnCommit(func() { s.count.Add(-1) })
		return nil
	})
}

// Update runs fn inside a write transaction. The mutated value is persisted
// whenever fn observably changed it, regardless of fn's return value. This is
// critical for security: failed unlock attempts must persist the incremented
// counter even when fn returns an error. When fn returns an error and made no
// observable change to the marshaled form, the write is skipped to avoid
// useless write amplification.
func (s *Store) Update(id string, fn func(*Secret) error) (*Secret, error) {
	var out Secret
	var fnErr error
	dbErr := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		original := append([]byte(nil), v...)
		if err := json.Unmarshal(v, &out); err != nil {
			return err
		}
		fnErr = fn(&out)
		data, err := json.Marshal(&out)
		if err != nil {
			return err
		}
		if fnErr != nil && bytes.Equal(original, data) {
			return nil
		}
		return b.Put([]byte(id), data)
	})
	if dbErr != nil {
		return nil, dbErr
	}
	return &out, fnErr
}

// PurgeExpired removes expired or consumed secrets older than grace.
func (s *Store) PurgeExpired(grace time.Duration) (int, error) {
	now := time.Now()
	var removed int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		c := b.Cursor()
		var toDelete [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var sec Secret
			if err := json.Unmarshal(v, &sec); err != nil {
				toDelete = append(toDelete, append([]byte(nil), k...))
				continue
			}
			if now.After(sec.ExpiresAt.Add(grace)) {
				toDelete = append(toDelete, append([]byte(nil), k...))
				continue
			}
			if sec.ConsumedAt != nil && now.After(sec.ConsumedAt.Add(grace)) {
				toDelete = append(toDelete, append([]byte(nil), k...))
			}
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			removed++
		}
		if removed > 0 {
			r := int64(removed)
			tx.OnCommit(func() { s.count.Add(-r) })
		}
		return nil
	})
	return removed, err
}
