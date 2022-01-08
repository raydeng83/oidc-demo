package repository

import (
	"github.com/raydeng83/oidc-demo/models"
	"gorm.io/gorm"
)

// CreateUser create a user
func CreateUser(user *models.User) (*models.User, error) {
	err := Db.Create(user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUsers get users from repo
func GetUsers(User *[]models.User) (err error) {
	err = Db.Find(User).Error
	if err != nil {
		return err
	}
	return nil
}

// GetUser gets user by id from repo
func GetUser(User *models.User, id int) (err error) {
	err = Db.Where("id = ?", id).First(User).Error
	if err != nil {
		return err
	}
	return nil
}

// GetUserByUsername gets user by username from repo
func GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := Db.Find(&user, models.User{Username: username}).Error
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// DeleteUser delete user
func DeleteUser(db *gorm.DB, User *models.User, id string) (err error) {
	err = db.Where("id = ?", id).Delete(User).Error
	if err != nil {
		return err
	}
	return nil
}
