package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	CreateAccount(*AccountGroup) error
	DeleteAccount(int) error
	UpdateAccount(int, *Account) error
	GetAccounts() ([]*AccountGroup, error)
	GetAccountID(int) ([]*AccountGroup, error)
	GetAccountPhone(int) (string, error)
	CheckAccountNameExists(string) (bool, error)
	CompareHashAndPW(int, []byte) error
	ChangePassword(int, string) error
	GetAccount(int) ([]*AccountGroup, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=antenna password=gobank sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	//defer db.Close()
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `CREATE TABLE  if not exists users(
		user_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		accountname VARCHAR(100),
		password BYTEA NOT NULL,
		username VARCHAR(50),
		permission_id INT,
		phone_number VARCHAR(100),
		status VARCHAR(10),
		groupid INT,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	  );`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) CreateAccount(acc *AccountGroup) error {
	query := `INSERT INTO users(accountname, password, username, permission_id, phone_number, status, groupid, created_at, updated_at)      
	VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)      
	RETURNING user_id`

	password, err := bcryptPW(acc.Account.Password)
	if err != nil {
		return err
	}

	phoneNumber, err := EncryptPhoneNumber(acc.Account.PhoneNumber)
	if err != nil {
		return err
	}

	resp := s.db.QueryRow(query,
		acc.Account.AccountName,
		password,
		acc.Account.Username,
		acc.Account.PermissionID,
		phoneNumber,
		acc.Account.Status,
		acc.Account.GroupID,
	)
	if err != nil {
		return err
	}

	var newID int
	if err := resp.Scan(&newID); err != nil {
		return err
	}
	err = s.updateGroupUserIDS(newID, acc.Account.GroupID)
	if err != nil {
		return err
	}

	//fmt.Printf("New ID is: %d\n", newID)
	return nil

}
func (s *PostgresStore) DeleteAccount(id int) error {
	groupid, err := s.getAccountGroupID(id)
	if err != nil {
		return err
	}

	// 删除用户
	_, err = s.db.Exec("DELETE FROM users WHERE user_id = $1", id)
	if err != nil {
		return err
	}

	// 删除用户ID
	err = s.deleteGroupUserID(id, groupid)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) UpdateAccount(id int, acc *Account) error {

	groupid, err := s.getAccountGroupID(id)
	if err != nil {
		return err
	}
	//删除group表中user_ids
	err = s.deleteGroupUserID(id, groupid)
	if err != nil {
		return err
	}

	err = s.updateGroupUserIDS(id, acc.GroupID)
	if err != nil {
		return err
	}

	if acc.Password != "" {
		password, err := bcryptPW(acc.Password)
		if err != nil {
			return err
		}
		acc.Password = string(password)
	}

	if acc.PhoneNumber != "" {
		encryptedPhone, err := EncryptPhoneNumber(acc.PhoneNumber)
		if err != nil {
			return err
		}
		acc.PhoneNumber = encryptedPhone
	}

	query := `UPDATE users  
          SET accountname = $1,  
              password = $2,  
              username = $3,  
              permission_id = $4,  
              phone_number = $5,  
              status = $6,
              groupid = $7,
              updated_at = $8 
          WHERE user_id = $9`

	_, err = s.db.Exec(query,
		acc.AccountName,
		acc.Password,
		acc.Username,
		acc.PermissionID,
		acc.PhoneNumber,
		acc.Status,
		acc.GroupID,
		time.Now(),
		id,
	)
	if err != nil {
		return err
	}

	return nil
}
func (s *PostgresStore) getAccountGroupID(id int) (int, error) {
	query := `SELECT groupid FROM users WHERE user_id = $1`
	row := s.db.QueryRow(query, id)
	var groupID int
	err := row.Scan(&groupID)
	if err != nil {
		return 0, err
	}
	return groupID, err

}

// func (s *PostgresStore) getAllGroupUserIDs(groupid int) (string, error) {
// 	query := `
// 		SELECT STRING_AGG(user_id::text, ',') AS user_ids_list
// 		FROM (
// 			SELECT unnest(user_ids) AS user_id
// 			FROM "group"
// 			WHERE id = $1 OR parent_id = $2
// 		) AS subquery;
// 	`
// 	rows, err := s.db.Query(query, groupid, groupid)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer rows.Close()

// 	var combinedUserIDs []byte
// 	if rows.Next() {
// 		err := rows.Scan(&combinedUserIDs)
// 		if err != nil {
// 			return "", err
// 		}
// 	}

// 	if len(combinedUserIDs) == 0 {
// 		return "", fmt.Errorf("no user IDs found")
// 	}

// 	combinedUserIDs = bytes.TrimSpace(combinedUserIDs)
// 	inClause := fmt.Sprintf("userid IN %s", combinedUserIDs)

// 	return inClause, nil

// }

func (s *PostgresStore) getAllGroupUserIDs(groupid int) ([]int, error) {
	query := `
		SELECT STRING_AGG(user_id::text, ',') AS user_ids_list
		FROM (
			SELECT unnest(user_ids) AS user_id
			FROM "group"
			WHERE id = $1 OR parent_id = $2
		) AS subquery;
	`
	rows, err := s.db.Query(query, groupid, groupid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var combinedUserIDs string
	if rows.Next() {
		err := rows.Scan(&combinedUserIDs)
		if err != nil {
			return nil, err
		}
	}

	if len(combinedUserIDs) == 0 {
		return nil, fmt.Errorf("no user IDs found")
	}

	// Split the comma-separated string into an array of strings
	userIDsStrArray := strings.Split(combinedUserIDs, ",")

	// Convert each string to an integer
	var userIDsInt []int
	for _, idStr := range userIDsStrArray {
		userID, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, err
		}

		userIDsInt = append(userIDsInt, userID)
	}

	return userIDsInt, nil
}

// func (s *PostgresStore) GetAccountID(id int) (*AccountGroup, error) {
// 	permid, err := s.GetAccountPermissionID(id)
// 	if err != nil {
// 		return nil, err
// 	}
// 	groupid, err := s.getAccountGroupID(id)
// 	if err != nil {
// 		return nil, err
// 	}
// 	fmt.Println(permid)
// 	alluserids, err := s.getAllGroupUserIDs(groupid)
// 	if err != nil {
// 		return nil, err
// 	}
// 	fmt.Println(alluserids)
// 	var query string
// 	var args []interface{}
// 	// 超级管理员
// 	if permid == 0 {
// 		query = `SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id`
// 	} else if permid == 1 {
// 		query = `SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = ANY($1::integer[])`
// 		var stringUserIDs []string
// 		for _, id := range alluserids {
// 			stringUserIDs = append(stringUserIDs, strconv.Itoa(id))
// 		}
// 		args = append(args, pq.Array(stringUserIDs))
// 	} else if permid == 2 {
// 		query = `SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = $1`
// 		args = append(args, id)
// 	} else {
// 		return nil, fmt.Errorf("unknown permission ID: %d", permid)
// 	}

//		rows, err := s.db.Query(query, args...)
//		if err != nil {
//			return nil, err
//		}
//		for rows.Next() {
//			return scanIntoAccount(rows)
//		}
//		return nil, fmt.Errorf("account id %d is not found ", id)
//	}
func (s *PostgresStore) GetAccountID(id int) ([]*AccountGroup, error) {
	permid, err := s.GetAccountPermissionID(id)
	if err != nil {
		return nil, err
	}
	groupid, err := s.getAccountGroupID(id)
	if err != nil {
		return nil, err
	}
	//fmt.Println(permid)
	alluserids, err := s.getAllGroupUserIDs(groupid)
	if err != nil {
		return nil, err
	}
	//fmt.Println(alluserids)
	var query string
	var args []interface{}
	// 超级管理员
	if permid == 0 {
		query = `SELECT users.user_id,users.accountname,users.username,users.permission_id,users.phone_number,users.status,users.groupid, "group".id,"group".name,"group".parent_id FROM users JOIN "group" ON users.groupid = "group".id`
	} else if permid == 1 {
		// 查询多条数据
		query = `SELECT users.user_id,users.accountname,users.username,users.permission_id,users.phone_number,users.status,users.groupid, "group".id,"group".name,"group".parent_id FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = ANY($1::integer[])`
		var stringUserIDs []string
		for _, id := range alluserids {
			stringUserIDs = append(stringUserIDs, strconv.Itoa(id))
		}
		args = append(args, pq.Array(stringUserIDs))
	} else if permid == 2 {
		// 查询一条数据
		query = `SELECT users.user_id,users.accountname,users.username,users.permission_id,users.phone_number,users.status,users.groupid, "group".id,"group".name,"group".parent_id FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = $1`
		args = append(args, id)
	} else {
		return nil, fmt.Errorf("unknown permission ID: %d", permid)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 定义一个切片保存查询结果
	var accounts []*AccountGroup

	// 循环遍历结果集
	for rows.Next() {
		account := new(AccountGroup)
		err := rows.Scan(
			&account.Account.ID,
			&account.Account.AccountName,
			&account.Account.Username,
			&account.Account.PermissionID,
			&account.Account.PhoneNumber,
			&account.Account.Status,
			&account.Account.GroupID,
			&account.Group.ID,
			&account.Group.Name,
			&account.Group.ParentID,
		)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}

	// 检查查询过程中是否出现错误
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 如果是 permid = 2 且没有查询到数据，返回错误
	if permid == 2 && len(accounts) == 0 {
		return nil, fmt.Errorf("account id %d is not found", id)
	}

	return accounts, nil
}

//取得单个id账户的信息

func (s *PostgresStore) GetAccount(id int) ([]*AccountGroup, error) {

	query := `SELECT users.user_id,users.accountname,users.username,users.permission_id,users.phone_number,users.status,users.groupid, "group".id,"group".name,"group".parent_id FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = $1`
	rows, err := s.db.Query(query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []*AccountGroup
	for rows.Next() {
		account := new(AccountGroup)
		err := rows.Scan(
			&account.Account.ID,
			&account.Account.AccountName,
			&account.Account.Username,
			&account.Account.PermissionID,
			&account.Account.PhoneNumber,
			&account.Account.Status,
			&account.Account.GroupID,
			&account.Group.ID,
			&account.Group.Name,
			&account.Group.ParentID,
		)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return accounts, nil
}

// 取得账户下所有
func (s *PostgresStore) GetAccounts() ([]*AccountGroup, error) {

	query := `SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var AccountGroups []*AccountGroup
	for rows.Next() {
		account, err := scanIntoAccount(rows)
		if err != nil {
			return nil, err
		}
		AccountGroups = append(AccountGroups, account)
	}
	return AccountGroups, nil
}

func scanIntoAccount(rows *sql.Rows) (*AccountGroup, error) {
	var account AccountGroup
	//account := new(Account)
	err := rows.Scan(
		&account.Account.ID,
		&account.Account.AccountName,
		&account.Account.Password,
		&account.Account.Username,
		&account.Account.PermissionID,
		&account.Account.PhoneNumber,
		&account.Account.Status,
		&account.Account.GroupID,
		&account.Account.CreatedAt,
		&account.Account.UpdatedAt,
		&account.Group.ID,
		&account.Group.CreatedAt,
		&account.Group.UpdatedAt,
		&account.Group.DeletedAt,
		&account.Group.Name,
		&account.Group.OrgID,
		&account.Group.ParentID,
		pq.Array(&account.Group.UserIDs),
	)
	if err != nil {
		return nil, err
	}

	if account.UserIDsJson != nil {
		err = json.Unmarshal(account.UserIDsJson, &account.Group.UserIDs)
		if err != nil {
			return nil, err
		}
	}

	decryptPhone, err := DecryptPhoneNumber(account.Account.PhoneNumber)
	if err != nil {
		return nil, err
	}
	account.Account.PhoneNumber = decryptPhone
	return &account, nil
}

func (s *PostgresStore) getAccountPW(id int) ([]byte, error) {

	var password string

	err := s.db.QueryRow("select password from users where user_id = $1", id).Scan(&password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("given ID not found")
		}
		return nil, err
	}
	return []byte(password), nil
}

func (s *PostgresStore) CompareHashAndPW(id int, userPassword []byte) error {

	hashAndPw, err := s.getAccountPW(id)
	if err != nil {
		return fmt.Errorf("given id not found")
	}

	if err := bcrypt.CompareHashAndPassword(hashAndPw, userPassword); err != nil {
		return fmt.Errorf("password verification failed: %w", err)
	}
	return nil

}

func bcryptPW(password string) ([]byte, error) {

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash password: %w", err)
	}
	return hashPassword, err
}

// 生产环境应该将decryptPhoneKey 存入到环境变量中
const decryptPhoneKey = "f3125f744df88a6b53bb3c4f18f5debc"

func EncryptPhoneNumber(phoneNumber string) (string, error) {
	key := []byte(decryptPhoneKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	padding := block.BlockSize() - len(phoneNumber)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	phoneNumber = phoneNumber + string(padtext)

	ciphertext := make([]byte, aes.BlockSize+len(phoneNumber))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(phoneNumber))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptPhoneNumber(cipherText string) (string, error) {
	key := []byte(decryptPhoneKey)
	ciphertext, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	padding := int(ciphertext[len(ciphertext)-1])
	if padding < 1 || padding > aes.BlockSize {
		return "", fmt.Errorf("invalid padding")
	}

	return string(ciphertext[:len(ciphertext)-padding]), nil
}

// Testing
func (s *PostgresStore) GetAccountPhone(id int) (string, error) {

	var phone string

	err := s.db.QueryRow("select phone_number from users where user_id = $1", id).Scan(&phone)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("given ID not found")
		}
		return "", err
	}
	return phone, nil
}

func (s *PostgresStore) CheckAccountNameExists(accountName string) (bool, error) {

	query := `SELECT EXISTS(SELECT 1 FROM users WHERE accountname = $1)`
	var exists bool
	err := s.db.QueryRow(query, accountName).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (s *PostgresStore) ChangePassword(id int, newPassword string) error {
	password, err := bcryptPW(newPassword)
	if err != nil {
		return err
	}
	query := "UPDATE users SET password = $1 WHERE user_id = $2"
	_, err = s.db.Exec(query, password, id)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) SelectAccountGroup(AccountName, Status string, id, groupid int) ([]AccountGroup, error) {

	permid, err := s.GetAccountPermissionID(id)
	if err != nil {
		return nil, err
	}
	var query string
	var rows *sql.Rows
	//超级管理员
	if permid == 0 {
		query = `SELECT users.*, groups.* FROM users JOIN "group" ON users.groupid = "group".id`
		rows, err = s.db.Query(query)

	}
	//管理员
	if permid == 1 {
		query = `SELECT users.*, groups.* FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = $1 AND users.user_id IN (SELECT unnest(user_ids) FROM "group")`
		rows, err = s.db.Query(query, id)
	}
	//普通用户
	if permid == 2 {
		query = `SELECT users.*, groups.* FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = $1`
		rows, err = s.db.Query(query, id)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var AccountGroups []AccountGroup
	for rows.Next() {
		var ug AccountGroup
		err := rows.Scan(&ug.Account.ID,
			&ug.Account.Username,
			&ug.Account.PhoneNumber,
			&ug.Account.Status,
			&ug.Account.AccountName,
			&ug.Account.PermissionID,
			&ug.Group.ID,
			&ug.Group.Name)
		if err != nil {
			return nil, err
		}
		AccountGroups = append(AccountGroups, ug)
	}
	if err := rows.Err(); err != nil {

		return nil, err
	}
	return AccountGroups, nil
}

func (s *PostgresStore) GetAccountPermissionID(id int) (int, error) {

	var permissionID int

	err := s.db.QueryRow("select permission_id from users where user_id = $1", id).Scan(&permissionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return id, nil
		}
		return id, err
	}
	return permissionID, nil
}

func (s *PostgresStore) updateGroupUserIDS(id, groupid int) error {
	// 查询当前 group 的 user_ids
	var currentUserIDs []string
	err := s.db.QueryRow("SELECT user_ids FROM \"group\" WHERE id = $1", groupid).Scan(pq.Array(&currentUserIDs))

	if err != nil {
		panic(err)
	}

	// 检查 id 是否已经存在于 user_ids 中
	for _, existingID := range currentUserIDs {
		if existingID == strconv.Itoa(id) {
			// 如果 id 已存在，不执行更新
			return nil
		}
	}

	// 如果 id 不存在，将其添加到 user_ids 中
	newUserIDs := append(currentUserIDs, strconv.Itoa(id))

	// 执行数据库更新
	_, err = s.db.Exec("UPDATE \"group\" SET user_ids = $1 WHERE id = $2", pq.Array(newUserIDs), groupid)
	if err != nil {
		panic(err)
	}

	return nil
}

// func (s *PostgresStore) updateGroupUserIDS(id, groupid int) error {

// 	newUserIDStr := fmt.Sprintf("%d", id)
// 	var currentUserIDs []string
// 	err := s.db.QueryRow("SELECT user_ids FROM \"group\" WHERE id = $1", groupid).Scan(pq.Array(&currentUserIDs))

// 	if err != nil {
// 		panic(err)
// 	}
// 	newUserIDs := append(currentUserIDs, newUserIDStr)
// 	//userIDsStr := strings.Join(newUserIDs, ",")
// 	//_, err = s.db.Exec("UPDATE \"group\" SET user_ids = ARRAY[:"+userIDsStr+"] WHERE id = ?", pq.Array(newUserIDs), groupid)
// 	_, err = s.db.Exec("UPDATE \"group\" SET user_ids = $1 WHERE id = $2", pq.Array(newUserIDs), groupid)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return err

// }

func (s *PostgresStore) deleteGroupUserID(userID, groupID int) error {
	// 获取当前用户ID数组
	var currentUserIDs []string
	err := s.db.QueryRow("SELECT user_ids FROM \"group\" WHERE id = $1", groupID).Scan(pq.Array(&currentUserIDs))
	if err != nil {
		return err
	}

	// 将要删除的用户ID转换为字符串
	userIDStr := strconv.Itoa(userID)

	// 从数组中移除要删除的用户ID
	var newUserIDs []string
	for _, id := range currentUserIDs {
		if id != userIDStr {
			newUserIDs = append(newUserIDs, id)
		}
	}

	// 更新数据库中的用户ID数组
	_, err = s.db.Exec("UPDATE \"group\" SET user_ids = $1 WHERE id = $2", pq.Array(newUserIDs), groupID)
	if err != nil {
		return err
	}

	return nil
}
