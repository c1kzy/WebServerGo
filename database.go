package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

func newDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mu:   &sync.RWMutex{},
	}
	err := db.EnsureDB()
	return db, err
}

func (db *DB) CreateDB() error {
	dbStructure := DBStructure{
		Chirps:      map[int]Chirp{},
		Users:       map[int]User{},
		Revocations: map[string]Revocation{},
	}
	return db.WriteDB(dbStructure)
}

func (db *DB) EnsureDB() error {
	_, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return db.CreateDB()
	}
	return err
}

func (db *DB) LoadDB() (DBStructure, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dbStructure := DBStructure{}
	dat, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return dbStructure, err
	}
	err = json.Unmarshal(dat, &dbStructure)
	if err != nil {
		return dbStructure, err
	}

	return dbStructure, nil
}

func (db *DB) WriteDB(dbStructure DBStructure) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	dat, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, dat, 0600)
	if err != nil {
		return err
	}
	return nil
}
