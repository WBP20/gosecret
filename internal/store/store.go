package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrNotFound  = errors.New("secret not found")
	ErrConsumed  = errors.New("secret already consumed")
	ErrExpired   = errors.New("secret expired")
	ErrLocked    = errors.New("too many failed attempts")
)

var bucket = []byte("secrets")

type Secret struct {
	ID           string     `json:"id"`
	Ciphertext   []byte     `json:"ct"`
	IV           []byte     `json:"iv"`
	Question     string     `json:"q,omitempty"`
	AnswerHash   []byte     `json:"ah,omitempty"`
	MaxAttempts  int        `json:"ma"`
	Attempts     int        `json:"at"`
	ExpiresAt    time.Time  `json:"exp"`
	ConsumedAt   *time.Time `json:"cat,omitempty"`
	UnlockedAt   *time.Time `json:"uat,omitempty"`
	CreatedAt    time.Time  `json:"ct_at"`
}

type Store struct {
	db *bolt.DB
}

func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucket)
		return e
	})
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Count() (int, error) {
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucket).Stats().KeyN
		return nil
	})
	return n, err
}

var ErrCapacity = errors.New("at capacity")

func (s *Store) Put(sec *Secret) error {
	return s.PutIfUnder(sec, 0)
}

func (s *Store) PutIfUnder(sec *Secret, maxKeys int) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if maxKeys > 0 && b.Stats().KeyN >= maxKeys {
			return ErrCapacity
		}
		data, err := json.Marshal(sec)
		if err != nil {
			return err
		}
		return b.Put([]byte(sec.ID), data)
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
		return tx.Bucket(bucket).Delete([]byte(id))
	})
}

// Update runs fn inside a write transaction. fn may mutate the secret; the
// mutated value is ALWAYS persisted regardless of fn's return value.
// This is critical for security: failed unlock attempts must persist the
// incremented counter even when fn returns an error.
func (s *Store) Update(id string, fn func(*Secret) error) (*Secret, error) {
	var out Secret
	var fnErr error
	dbErr := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		v := b.Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		if err := json.Unmarshal(v, &out); err != nil {
			return err
		}
		fnErr = fn(&out)
		data, err := json.Marshal(&out)
		if err != nil {
			return err
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
		return nil
	})
	return removed, err
}
