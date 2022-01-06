package models

type User struct {
	Username  string `json:"username" `
	Password  string `json:"password" `
	FirstName string `json:"firstName" `
	LastName  string `json:"lastName" `
	Email     string `json:"email" `
}
