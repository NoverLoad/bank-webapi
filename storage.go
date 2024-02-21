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
	UpdateAccount(int, *AccountGroup) error
	GetAccounts() ([]*AccountGroup, error)
	GetAccountID(int) (*AccountGroup, error)
	GetAccountPhone(int) (string, error)
	CheckAccountNameExists(string) (bool, error)
	CompareHashAndPW(int, []byte) error
	ChangePassword(int, string) error
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

	fmt.Printf("New ID is: %d\n", newID)
	return nil

}
func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Query("delete from users where user_id = $1", id)
	return err
}

func (s *PostgresStore) UpdateAccount(id int, acc *AccountGroup) error {

	if acc.Account.Password != "" {
		password, err := bcryptPW(acc.Account.Password)
		if err != nil {
			return err
		}
		acc.Account.Password = string(password)
	}

	if acc.Account.PhoneNumber != "" {
		encryptedPhone, err := EncryptPhoneNumber(acc.Account.PhoneNumber)
		if err != nil {
			return err
		}
		acc.Account.PhoneNumber = encryptedPhone
	}

	query := `UPDATE users  
              SET accountname = $1,  
                  password = $2,  
                  username = $3,  
                  permission_id = $4,  
                  phone_number = $5,  
                  status = $6,
				  groupid =$7  
                  updated_at = $8 
              WHERE user_id = $9`

	_, err := s.db.Exec(query,
		acc.Account.AccountName,
		acc.Account.Password,
		acc.Account.Username,
		acc.Account.PermissionID,
		acc.Account.PhoneNumber,
		acc.Account.Status,
		acc.Account.GroupID,
		time.Now(),
		id,
	)
	fmt.Println(id)
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

func (s *PostgresStore) getAllGroupUserIDs(groupid int) (string, error) {
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
		return "", err
	}
	defer rows.Close()

	var combinedUserIDs []byte
	if rows.Next() {
		err := rows.Scan(&combinedUserIDs)
		if err != nil {
			return "", err
		}
	}

	if len(combinedUserIDs) == 0 {
		return "", fmt.Errorf("no user IDs found")
	}

	combinedUserIDs = bytes.TrimSpace(combinedUserIDs)
	inClause := fmt.Sprintf("userid IN %s", combinedUserIDs)

	return inClause, nil

}
func (s *PostgresStore) GetAccountID(id int) (*AccountGroup, error) {
	permid, err := s.GetAccountPermissionID(id)
	if err != nil {
		return nil, err
	}
	groupid, err := s.getAccountGroupID(id)
	if err != nil {
		return nil, err
	}
	fmt.Println(permid)
	alluserids, err := s.getAllGroupUserIDs(groupid)
	if err != nil {
		return nil, err
	}
	fmt.Println(alluserids)
	var query string
	var args []interface{}
	// 超级管理员
	if permid == 0 {
		query = `SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id`
	} else if permid == 1 {
		// 假设 alluserids 是一个逗号分隔的用户ID字符串，例如 "1,2,3,4,5"
		// 使用 strings.Split 将字符串分割为 ID 切片
		userIDs := strings.Split(alluserids, ",")

		// 清理 userIDs 切片，去除空字符串和前后空格
		var cleanedUserIDs []string
		for _, userID := range userIDs {
			userID = strings.TrimSpace(userID)
			if userID != "" {
				cleanedUserIDs = append(cleanedUserIDs, userID)
			}
		}

		// 如果没有有效的用户ID，返回错误
		if len(cleanedUserIDs) == 0 {
			return nil, fmt.Errorf("no valid user IDs found in alluserids")
		}

		// 构造 IN 子句的参数占位符和参数值列表
		var paramPlaceholders []string
		var paramValues []interface{}
		for _, userID := range cleanedUserIDs {
			// 为每个用户ID添加参数占位符
			paramPlaceholders = append(paramPlaceholders, "$"+strconv.Itoa(len(paramValues)+1))
			// 将用户ID作为参数值
			args = append(args, userID)
		}

		// 构建查询字符串，使用参数占位符
		query = fmt.Sprintf(`SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = ANY(%s)`, strings.Join(paramPlaceholders, ","))

	} else if permid == 2 {
		query = `SELECT users.*, "group".* FROM users JOIN "group" ON users.groupid = "group".id WHERE users.user_id = $1`
		args = append(args, id)
	} else {
		return nil, fmt.Errorf("unknown permission ID: %d", permid)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account id %d is not found ", id)
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

	newUserIDStr := fmt.Sprintf("%d", id)
	var currentUserIDs []string
	err := s.db.QueryRow("SELECT user_ids FROM \"group\" WHERE id = $1", groupid).Scan(pq.Array(&currentUserIDs))

	if err != nil {
		panic(err)
	}
	newUserIDs := append(currentUserIDs, newUserIDStr)
	//userIDsStr := strings.Join(newUserIDs, ",")
	//_, err = s.db.Exec("UPDATE \"group\" SET user_ids = ARRAY[:"+userIDsStr+"] WHERE id = ?", pq.Array(newUserIDs), groupid)
	_, err = s.db.Exec("UPDATE \"group\" SET user_ids = $1 WHERE id = $2", pq.Array(newUserIDs), groupid)
	if err != nil {
		panic(err)
	}
	return err

}
