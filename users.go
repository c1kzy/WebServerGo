package main

import (
	"errors"
	"os"
)

func (db *DB) CreateUser(email, hashedPassword string) (User, error) {
	if _, err := db.GetUserByEmail(email); !errors.Is(err, os.ErrNotExist) {
		return User{}, ErrAlreadyExists
	}

	dbStructure, err := db.LoadDB()
	if err != nil {
		return User{}, err
	}

	id := len(dbStructure.Users) + 1
	user := User{
		Email:          email,
		HashedPassword: hashedPassword,
		ID:             id,
	}
	dbStructure.Users[id] = user

	err = db.WriteDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) GetUser(id int) (User, error) {
	dbStructure, err := db.LoadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := dbStructure.Users[id]
	if !ok {
		return User{}, os.ErrNotExist
	}

	return user, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	dbStructure, err := db.LoadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, os.ErrNotExist
}

func (db *DB) UpdateUser(id int, email, hashedPassword string) (User, error) {
	dbStructure, err := db.LoadDB()
	if err != nil {
		return User{}, err
	}
	user, ok := dbStructure.Users[id]
	if !ok {
		return User{}, os.ErrNotExist
	}
	user.Email = email
	user.HashedPassword = hashedPassword
	dbStructure.Users[id] = user

	err = db.WriteDB(dbStructure)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (db *DB) UpgradeChirpyRed(id int) (User, error) {
	dbStructure, err := db.LoadDB()
	if err != nil {
		return User{}, err
	}
	user, ok := dbStructure.Users[id]
	if !ok {
		return User{}, os.ErrNotExist
	}
	user.IsChirpyRed = true
	dbStructure.Users[id] = user
	err = db.WriteDB(dbStructure)
	if err != nil {
		return User{}, err
	}
	return user, nil
}
