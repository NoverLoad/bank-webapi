package main

import (
	"time"
)

type AccountPW struct {
	Password  string    `json:"password"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func NewAccountPW(Password string) *AccountPW {
	return &AccountPW{
		Password:  Password,
		UpdatedAt: time.Now(),
	}
}

type Account struct {
	ID           int       `json:"id"`
	AccountName  string    `json:"accountName"`
	Password     string    `json:"password"`
	Username     string    `json:"username"`
	PermissionID int       `json:"permissionID"`
	PhoneNumber  string    `json:"phoneNumber"`
	Status       string    `json:"status"`
	GroupID      int       `json:"groupid"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Group struct {
	ID        int        `json:"id" gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at"`
	Name      string     `json:"name"`
	OrgID     int        `json:"org_id"`
	ParentID  int        `json:"parent_id"`
	UserIDs   []string   `json:"user_ids" gorm:"type:text[]"`
}

type AccountGroup struct {
	Account     Account
	Group       Group
	UserIDsJson []byte `json:"users_json"`
}

// GroupID int
func NewAccount(AccountName, Password, Username string, PermissionID int, PhoneNumber, Status string, GroupID int) *Account {
	return &Account{
		AccountName:  AccountName,
		Password:     Password,
		Username:     Username,
		PermissionID: PermissionID,
		PhoneNumber:  PhoneNumber,
		Status:       Status,
		GroupID:      GroupID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func NewAccountGroup(AccountName, Password, Username string, PermissionID int, PhoneNumber, Status string, GroupID int) *AccountGroup {

	account := Account{
		AccountName:  AccountName,
		Password:     Password,
		Username:     Username,
		PermissionID: PermissionID,
		PhoneNumber:  PhoneNumber,
		Status:       Status,
		GroupID:      GroupID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	group := Group{
		Name:     "A公司",
		ParentID: 1,
	}
	return &AccountGroup{
		Account: account,
		Group:   group,
	}
}
