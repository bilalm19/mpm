package server

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type userTracker struct {
	UserMap      map[string]credentials
	trackerMutex sync.Mutex
}

func newUserTracker() userTracker {
	return userTracker{
		UserMap: make(map[string]credentials),
	}
}

// Track which users have been added to the database
var globalUserTracker = newUserTracker()

type DuplicateUser struct {
	Err error
}

type MissedAccountCreation struct {
	Err error
}

type UserDatabaseNotEmpty struct {
	Err error
}

type SecretDatabaseNotEmpty struct {
	Err error
}

func (e *DuplicateUser) Error() string {
	return e.Err.Error()
}

func NewDuplicateUser(err error) error {
	return &DuplicateUser{err}
}

func (e *MissedAccountCreation) Error() string {
	return e.Err.Error()
}

func NewMissedAccountCreation(err error) error {
	return &MissedAccountCreation{err}
}

func (e *UserDatabaseNotEmpty) Error() string {
	return e.Err.Error()
}

func NewUserDatabaseNotEmpty(err error) error {
	return &UserDatabaseNotEmpty{err}
}

func (e *SecretDatabaseNotEmpty) Error() string {
	return e.Err.Error()
}

func NewSecretDatabaseNotEmpty(err error) error {
	return &SecretDatabaseNotEmpty{err}
}

func TestSimpleAccountCreation(t *testing.T) {
	var pass [10]chan bool
	users := prepareUsers()
	userMap := make(map[string]string)

	for i := range pass {
		userMap[users[i].Username] = users[i].Password
		pass[i] = make(chan bool)
		go requestAccountCreation(users[i], pass[i])
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Account creation request number %d failed", i)
		}
	}

	err := checkDatabase(len(userMap))
	if err != nil {
		switch err.(type) {
		case *DuplicateUser:
			t.Error(err)
		default:
			t.Fatal(err)
		}
	}
}

func TestSimpleAddSecrets(t *testing.T) {
	var pass [10]chan bool
	users := prepareUsers()

	for i := range pass {
		pass[i] = make(chan bool)
		go requestAddSecrets(users[i], pass[i], false)
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Add secret request number %d failed", i)
		}
	}
}

func TestSimpleGetSecrets(t *testing.T) {
	var pass [10]chan bool
	users := prepareUsers()

	for i := range pass {
		pass[i] = make(chan bool)
		go requestGetSecrets(users[i], pass[i], false)
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Get secret request number %d failed", i)
		}
	}
}

func TestSimpleDeleteAccount(t *testing.T) {
	var pass [10]chan bool
	users := prepareUsers()

	for i := range pass {
		pass[i] = make(chan bool)
		go requestDeleteAccount(users[i], pass[i])
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Delete account request number %d failed", i)
		}
	}
}

func TestChaoticRequests(t *testing.T) {
	var pass [10]chan bool
	var getpass [10]chan bool
	var delpass [10]chan bool

	users := prepareUsers()

	for i := range pass {
		pass[i] = make(chan bool)
		getpass[i] = make(chan bool)
		delpass[i] = make(chan bool)
		go requestAccountCreation(users[i], pass[i])
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Account creation request number %d failed", i)
		}
	}

	for i := range pass {
		go requestAddSecrets(users[i], pass[i], true)
		go requestGetSecrets(users[i], getpass[i], true)
		go requestDeleteAccount(users[i], delpass[i])
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Add secret request number %d failed", i)
		}

		if !<-getpass[i] {
			t.Errorf("Get secret request number %d failed", i)
		}

		if !<-delpass[i] {
			t.Errorf("Delete account request number %d failed", i)
		}
	}

	if err := checkDatabasesEmpty(); err != nil {
		switch err.(type) {
		case *UserDatabaseNotEmpty:
			t.Error(err)
		case *SecretDatabaseNotEmpty:
			t.Error(err)
		default:
			t.Fatal(err)
		}
	}
}

func requestAccountCreation(creds credentials, pass chan bool) {
	response, request, err := prepareRequest(creds, http.MethodPost)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	registerNewUser(response, request)
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	if string(respBody) != "Account created" && response.Code != http.StatusOK {
		if string(respBody) != "Username is already in use" && response.Code != http.StatusBadRequest {
			log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
			pass <- false
			return
		}
	} else {
		globalUserTracker.trackerMutex.Lock()
		globalUserTracker.UserMap[creds.Username] = creds
		globalUserTracker.trackerMutex.Unlock()
	}

	pass <- true
}

func checkDatabase(uniqueUserCount int) error {
	file, err := os.Open("db/users")
	if err != nil {
		return err
	}
	defer file.Close()

	users := make(map[string]string)
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		var creds credentialStorageStructure
		json.Unmarshal(line, &creds)

		if _, ok := users[creds.Username]; ok {
			log.Printf("%s found more than once.\n", creds.Username)
			return NewDuplicateUser(errors.New("mishandled duplication"))
		}
		users[creds.Username] = string(creds.Password)
	}

	if uniqueUserCount != len(users) {
		return NewMissedAccountCreation(errors.New(
			"the number of accounts created are less than the unique requests"))
	}

	return nil
}

func requestAddSecrets(userReq credentials, pass chan bool, chaos bool) {
	response, request, err := prepareRequest(userReq, http.MethodPost)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	serveClient(response, request)

	pass <- checkLoginResponse(userReq, response, chaos)
}

func requestGetSecrets(userReq credentials, pass chan bool, chaos bool) {
	response, request, err := prepareRequest(userReq, http.MethodGet)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	serveClient(response, request)
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	if globalUserTracker.UserMap[userReq.Username].Password != userReq.Password {
		if response.Code != http.StatusUnauthorized {
			log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
			pass <- false
			return
		}
	} else {
		if chaos && ((response.Code == http.StatusUnauthorized &&
			string(respBody) == "Authentication failed. Invalid username or password") ||
			response.Code == http.StatusNoContent) {
			pass <- true
			return
		}

		if userReq.SecretList == nil || len(userReq.SecretList) == 0 {
			if response.Code != http.StatusNoContent {
				log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
				pass <- false
				return
			}
		} else {
			pass <- checkResponseSecrets(userReq, respBody)
		}
	}

	pass <- true
}

func requestDeleteAccount(userReq credentials, pass chan bool) {
	response, request, err := prepareRequest(userReq, http.MethodDelete)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	deleteUser(response, request)
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	if globalUserTracker.UserMap[userReq.Username].Password != userReq.Password {
		if string(respBody) != "Authentication failed. Invalid username or password" &&
			response.Code != http.StatusUnauthorized {
			log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
			pass <- false
		}
	} else {
		if string(respBody) != "Your account has been deleted." && response.Code != http.StatusOK {
			if userReq.Username == "john" && string(respBody) == "Authentication failed. Invalid username or password" &&
				response.Code == http.StatusUnauthorized {
				pass <- true
				return
			} else {
				log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
				pass <- false
			}
		}
	}
	pass <- true
}

func prepareRequest(creds credentials, method string) (*httptest.ResponseRecorder, *http.Request, error) {
	marshalledCreds, err := json.Marshal(creds)
	if err != nil {
		return nil, nil, err
	}
	reqBody := strings.NewReader(string(marshalledCreds))
	request, err := http.NewRequest(method, "/", reqBody)
	if err != nil {
		return nil, nil, err
	}
	response := httptest.NewRecorder()

	return response, request, nil
}

func checkLoginResponse(userReq credentials, response *httptest.ResponseRecorder, chaos bool) bool {
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return false
	}

	// Since global variable is only going to be accessed for reading at this
	// point, there should be no issues with data races. Hence, no mutex lock.
	if globalUserTracker.UserMap[userReq.Username].Password != userReq.Password {
		if string(respBody) != "Authentication failed. Invalid username or password" &&
			response.Code != http.StatusUnauthorized {
			log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
			return false
		}
	} else {
		if chaos && response.Code == http.StatusUnauthorized &&
			string(respBody) == "Authentication failed. Invalid username or password" {
			return true
		}

		if userReq.SecretList == nil || len(userReq.SecretList) == 0 {
			if string(respBody) != "No secrets were sent in request" && response.Code != http.StatusBadRequest {
				log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
				return false
			} else {
				return true
			}
		}

		if string(respBody) != "Secrets added" && response.Code != http.StatusOK {
			log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
			return false
		}
	}

	return true
}

func checkResponseSecrets(userReq credentials, respBody []byte) bool {
	var err error
	secrets := make(map[string][]byte)
	if err = json.Unmarshal(respBody, &secrets); err != nil {
		log.Println(err)
		return false
	}

	for k, v := range secrets {
		secrets[k], err = decryptAESGCM([]byte(userReq.Password), v)
		if err != nil {
			log.Println(err)
			return false
		}
		if globalUserTracker.UserMap[userReq.Username].SecretList[k] != string(secrets[k]) {
			if userReq.Username != "john" || userReq.Password != "123" {
				return false
			}
		}
	}
	return true
}

func prepareUsers() (users [10]credentials) {
	for i := range users {
		users[i].SecretList = make(map[string]string)
	}

	users[0].Username = "john"
	users[0].Password = "123"
	users[0].SecretList["service1"] = "890"
	users[0].SecretList["service2"] = "890"

	users[1].Username = "john"
	users[1].Password = "123"
	users[1].SecretList["service6"] = "900"
	users[1].SecretList["service8"] = "790"

	users[2].Username = "jane"
	users[2].Password = "123"
	users[2].SecretList["service1"] = "1200"

	users[3].Username = "jane"
	users[3].Password = "1235"
	users[3].SecretList["service1"] = "001"
	users[3].SecretList["service3"] = "00"

	users[4].Username = "john"
	users[4].Password = "1238"
	users[4].SecretList["service1"] = "password"
	users[4].SecretList["service2"] = "password"

	users[5].Username = "bob"
	users[5].Password = "123"
	users[5].SecretList["service6"] = "password"

	users[6].Username = "set"
	users[6].Password = "123"
	users[6].SecretList["service1"] = "12345678"
	users[6].SecretList["service2"] = "123456789"
	users[6].SecretList["service3"] = "password1"
	users[6].SecretList["service4"] = "hunter2"

	users[7].Username = "bat"
	users[7].Password = "123"
	users[7].SecretList["service1"] = "12345678"

	users[8].Username = "nat"
	users[8].Password = "12345678"

	users[9].Username = "lat"
	users[9].Password = "password"
	users[9].SecretList["service5"] = "12345678"
	users[9].SecretList["service7"] = "87654321"

	return
}

func checkDatabasesEmpty() error {
	if err := checkDBEmpty("db/users"); err != nil {
		return err
	}

	if err := checkDBEmpty("db/secrets"); err != nil {
		return err
	}

	return nil
}

func checkDBEmpty(dbname string) error {
	file, err := os.Open(dbname)
	if err != nil {
		return err
	}
	defer file.Close()

	fs, err := file.Stat()
	if err != nil {
		return err
	}

	if fs.Size() != 0 {
		if dbname == "db/users" {
			return NewUserDatabaseNotEmpty(errors.New("user database is not empty"))
		} else {
			return NewSecretDatabaseNotEmpty(errors.New("secret database is not empty"))
		}
	}

	return nil
}

func decryptAESGCM(masterpass, ciphertext []byte) ([]byte, error) {
	keyLength := 2 * aes.BlockSize
	key := make([]byte, keyLength)

	if len(masterpass) >= keyLength {
		copy(key, masterpass[0:keyLength])
	} else {
		copy(key, masterpass)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce from the ciphertext
	nonce := ciphertext[:12]

	return aesgcm.Open(nil, nonce, ciphertext[12:], nil)
}
