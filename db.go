package main

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type User struct {
	Id           bson.ObjectId `bson:"_id,omitempty"`
	RefreshToken string        `bson:"refresh_token"`
}

type UsersRepository struct {
	UsersCollection *mgo.Collection
}

func (r *UsersRepository) Clear() (info *mgo.ChangeInfo, err error) {
	return r.UsersCollection.RemoveAll(bson.M{})
}

func (r *UsersRepository) Insert(user *User) error {
	return r.UsersCollection.Insert(user)
}

func (r *UsersRepository) Update(userId string, user *User) error {
	return r.UsersCollection.UpdateId(bson.ObjectIdHex(userId), user)
}

func (r *UsersRepository) UpdateRefreshToken(userId string, refreshToken string) error {
	return r.UsersCollection.UpdateId(bson.ObjectIdHex(userId), User{RefreshToken: refreshToken})
}

func (r *UsersRepository) FindAll() ([]User, error) {
	var users []User
	err := r.UsersCollection.Find(bson.M{}).All(&users)
	return users, err
}

func (r *UsersRepository) Find(userId string) (*User, error) {
	var user User
	err := r.UsersCollection.FindId(bson.ObjectIdHex(userId)).One(&user)
	return &user, err
}
