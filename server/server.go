package server

import (
	"encoding/json"
	"math/rand"
	"mpm/logger"
	"net/http"
	"os"
	"sync"
	"time"
)

var userDatabaseMutex = &sync.Mutex{}
var secretDatabaseMutex = &sync.Mutex{}
var dbDirectoryMutex = &sync.Mutex{}

type userCache struct {
	Users      map[string]uint8
	cacheMutex sync.Mutex
	Login      map[string]uint8 // cache for login endpoint
	LoginMutex sync.Mutex
}

// This cache keeps tracks of users whose account is in the process of being
// created, or the user's request is being processed. In the case of handling
// account creation, this prevents creation of duplicate accounts. For the case
// of login request, it prevents conflicts of service.
var cache = userCache{
	Users: make(map[string]uint8),
	Login: make(map[string]uint8),
}

type MPMServer struct {
	HTTPServer *http.Server
}

type credentials struct {
	Username   string
	Password   string
	SecretList map[string]string // Only used by login endpoint.
}

// credentialStorageStructure is the data structure used for storing the credentials in
// the file database.
type credentialStorageStructure struct {
	Username string
	Password []byte
}

// secretStorageStructure is the data structure used for storing the secrets in
// the file database.
type secretStorageStructure struct {
	Username   string
	SecretList map[string][]byte
}

// New creates and returns an MPMServer.
func New() MPMServer {
	http.DefaultServeMux = new(http.ServeMux)
	return MPMServer{
		&http.Server{
			Addr: ":2000",
		},
	}
}

// StartEdgeServer starts the server that listens for edge devices.
func (server *MPMServer) StartEdgeServer() error {
	// Initialize seed
	rand.Seed(time.Now().UnixNano())

	http.HandleFunc("/signup", registerNewUser)
	http.HandleFunc("/login", serveClient)
	return server.HTTPServer.ListenAndServe()
}

func registerNewUser(writer http.ResponseWriter, request *http.Request) {
	if request.Body == nil {
		respondClient(writer, http.StatusBadRequest, []byte("400 Bad Request"))
		return
	}

	creds, err := decodeClientMessage(request.Body, writer)
	if err != nil {
		logger.Error(err)
		return
	}

	// Check if another user with same account name is being created
	cache.cacheMutex.Lock()
	if _, ok := cache.Users[creds.Username]; !ok {
		cache.Users[creds.Username] = 1
	} else {
		respondClient(writer, http.StatusBadRequest, []byte("Username is already in use"))
		cache.cacheMutex.Unlock()
		return
	}
	cache.cacheMutex.Unlock()

	// Do not register user if username already exists.
	_, err = loadCredentials(creds.Username)
	if err != nil {
		switch err.(type) {
		case *UserDoesNotExist:
		case *os.PathError:
		default:
			logger.Error(err)
			freeUserCache(creds.Username)
			respondClient(writer, http.StatusInternalServerError, []byte("500 Server Error"))
			return
		}
		storeCredentials(creds)
		respondClient(writer, http.StatusOK, []byte("Account created"))

		freeUserCache(creds.Username)
	} else {
		freeUserCache(creds.Username)
		respondClient(writer, http.StatusBadRequest, []byte("Username is already in use"))
	}
}

func serveClient(writer http.ResponseWriter, request *http.Request) {
	if request.Body == nil {
		respondClient(writer, http.StatusBadRequest, []byte("400 Bad Request"))
		return
	}

	creds, err := decodeClientMessage(request.Body, writer)
	if err != nil {
		logger.Error(err)
		return
	}

	i := 1
	for {
		cache.LoginMutex.Lock()
		if _, ok := cache.Login[creds.Username]; !ok {
			cache.Login[creds.Username] = 1
			cache.LoginMutex.Unlock()
			break
		}
		cache.LoginMutex.Unlock()
		time.Sleep(time.Duration(i) * 200000000)
		if i <= 5 {
			i++
		}
	}

	if request.Method == http.MethodPost {
		if err = verifyLogin(creds, writer); err != nil {
			freeLoginCache(creds.Username)
			logger.Error(err)
			return
		}

		if creds.SecretList == nil || len(creds.SecretList) == 0 {
			freeLoginCache(creds.Username)
			respondClient(writer, http.StatusBadRequest, []byte("No secrets were sent in request"))
			return
		}

		if err = storeUserSecrets(creds); err != nil {
			freeLoginCache(creds.Username)
			logger.Error(err)
			respondClient(writer, http.StatusInternalServerError, []byte("500 Server Error"))
			return
		}

		respondClient(writer, http.StatusOK, []byte("Secrets added"))
	} else if request.Method == http.MethodGet {
		if err = verifyLogin(creds, writer); err != nil {
			freeLoginCache(creds.Username)
			logger.Error(err)
			return
		}
		secrets, err := getUserSecrets(creds.Username)
		if err != nil {
			switch err.(type) {
			case *os.PathError:
				respondClient(writer, http.StatusNoContent, []byte(""))
			case *NoSecrets:
				respondClient(writer, http.StatusNoContent, []byte(""))
			default:
				logger.Error(err)
				respondClient(writer, http.StatusInternalServerError, []byte("500 Server Error"))
			}
			freeLoginCache(creds.Username)
			return
		}

		marshalledSecrets, err := json.Marshal(secrets.SecretList)
		if err != nil {
			freeLoginCache(creds.Username)
			logger.Error(err)
			respondClient(writer, http.StatusInternalServerError, []byte("500 Server Error"))
			return
		}

		respondClient(writer, http.StatusOK, marshalledSecrets)

	} else if request.Method == http.MethodDelete {
		if err = verifyLogin(creds, writer); err != nil {
			freeLoginCache(creds.Username)
			logger.Error(err)
			return
		}

		err = deleteAccount(creds.Username)
		if err != nil {
			freeLoginCache(creds.Username)
			logger.Error(err)
			respondClient(writer, http.StatusInternalServerError, []byte("500 Server Error"))
			return
		}

		respondClient(writer, http.StatusOK, []byte("Your account has been deleted."))
	} else {
		respondClient(writer, http.StatusBadRequest, []byte("Invalid method"))
	}
	freeLoginCache(creds.Username)
}

// Free up cache
func freeUserCache(user string) {
	cache.cacheMutex.Lock()
	delete(cache.Users, user)
	cache.cacheMutex.Unlock()
}

// Free up cache
func freeLoginCache(user string) {
	cache.LoginMutex.Lock()
	delete(cache.Login, user)
	cache.LoginMutex.Unlock()
}
