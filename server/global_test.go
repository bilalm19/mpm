package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
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

func TestMPM(t *testing.T) {
	var pass [10]chan bool
	var users [10]credentials
	userMap := make(map[string]string)
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

	for i := range pass {
		go requestAddSecrets(users[i], pass[i])
	}

	for i := range pass {
		if !<-pass[i] {
			t.Errorf("Add secret request number %d failed", i)
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

func requestAddSecrets(userReq credentials, pass chan bool) {
	response, request, err := prepareRequest(userReq, http.MethodPost)
	if err != nil {
		log.Println(err)
		pass <- false
		return
	}

	serveClient(response, request)

	pass <- checkLoginResponse(userReq, response)
}

func requestGetSecrets(userReq credentials, pass chan bool) {
	_, _, err := prepareRequest(userReq, http.MethodGet)
	if err != nil {
		log.Println(err)
		pass <- false
		return
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

func checkLoginResponse(userReq credentials, response *httptest.ResponseRecorder) bool {
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return false
	}

	// Since global variable is only going to be accessed for reading at this
	// point, there should be no issues with data races. Hence, no mutex lock.
	if reflect.DeepEqual(globalUserTracker.UserMap[userReq.Username], userReq) {
		if globalUserTracker.UserMap[userReq.Username].SecretList == nil ||
			len(globalUserTracker.UserMap[userReq.Username].SecretList) == 0 {

			if string(respBody) != "No secrets were sent in request" && response.Code != http.StatusBadRequest {
				log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
				return false
			}

		}
	} else {
		if globalUserTracker.UserMap[userReq.Username].Password != userReq.Password {
			if string(respBody) != "Authentication failed. Invalid username or password" &&
				response.Code != http.StatusUnauthorized {
				log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
				return false
			}
		} else {
			if string(respBody) != "Secrets added" && response.Code != http.StatusOK {
				log.Printf("StatusCode: %d; Response: %s\n", response.Code, respBody)
				return false
			}
		}
	}

	return true
}

/*
 @TODO: Concurrent requests for adding accounts, deletion, getting secrets
 and adding secrets. Handle duplication and wrong addition/deletion.
 Possibly need queue?
*/
