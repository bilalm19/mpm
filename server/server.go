package server

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"mpm/logger"
	"net/http"
	"os"
	"reflect"
	"time"

	"golang.org/x/crypto/argon2"
)

type MPMServer struct {
	HTTPServer *http.Server
}

type Credentials struct {
	Username   string
	Password   string
	SecretList map[string]string // Only used by login endpoint.
}

// CredentialStorageStructure is the data structure used for storing the credentials in
// the file database.
type CredentialStorageStructure struct {
	Username string
	Password []byte
	Salt     []byte
}

// SecretStorageStructure is the data structure used for storing the secrets in
// the file database.
type SecretStorageStructure struct {
	Username   string
	SecretList map[string]string
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
	creds, err := decodeClientMessage(request.Body, writer)
	if err != nil {
		logger.Error(err)
		return
	}

	// Do not register user if username already exists.
	_, err = loadCredentials(creds.Username)
	if err != nil {
		switch err.(type) {
		case *UserDoesNotExist:
			storeCredentials(creds)
		case *os.PathError:
			storeCredentials(creds)
		default:
			logger.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte("500 Server Error"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("Account created"))
	} else {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Username is already in use"))
	}
}

func serveClient(writer http.ResponseWriter, request *http.Request) {
	creds, err := decodeClientMessage(request.Body, writer)
	if err != nil {
		logger.Error(err)
		return
	}

	if request.Method == http.MethodPost {
		if err = verifyLogin(creds, writer); err != nil {
			logger.Error(err)
			return
		}
		if err = storeUserSecrets(creds); err != nil {
			logger.Error(err)
			return
		}

		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("Secret added"))
	} else if request.Method == http.MethodGet {
		if err = verifyLogin(creds, writer); err != nil {
			logger.Error(err)
			return
		}
		if err = getUserSecrets(creds.Username); err != nil {
			logger.Error(err)
			return
		}

	} else if request.Method == http.MethodDelete {
		if err = verifyLogin(creds, writer); err != nil {
			logger.Error(err)
			return
		}
	} else {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Invalid method"))
	}
}

func decodeClientMessage(body io.ReadCloser, writer http.ResponseWriter) (Credentials, error) {
	decoder := json.NewDecoder(body)
	var creds Credentials
	err := decoder.Decode(&creds)
	if err != nil {
		logger.Error(err)
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("500 Server Error"))
		return creds, err
	}

	return creds, nil
}

func storeCredentials(creds Credentials) error {
	randNum := rand.Uint32()
	salt := make([]byte, 4)
	binary.LittleEndian.PutUint32(salt, randNum)
	key := argon2.IDKey([]byte(creds.Password), salt, 1, 64*1024, 4, 32)

	os.MkdirAll("db", os.ModePerm)

	storeUser, err := json.Marshal(CredentialStorageStructure{
		Username: creds.Username,
		Password: key,
		Salt:     salt,
	})
	storeUser = append(storeUser, []byte("\n")...)
	if err != nil {
		return err
	}

	f, err := os.OpenFile("db/users", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.Write(storeUser); err != nil {
		return err
	}

	return nil
}

func verifyLogin(creds Credentials, writer http.ResponseWriter) error {
	storedCreds, err := loadCredentials(creds.Username)
	if err != nil {
		switch err.(type) {
		case *UserDoesNotExist:
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Authentication failed. Invalid username or password"))
		// case *NoSecrets:
		// 	writer.WriteHeader(http.StatusNoContent)
		// 	writer.Write([]byte("You do not have any secrets stored."))
		default:
			logger.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte("500 Server Error"))
		}
		return err
	}

	key := argon2.IDKey([]byte(creds.Password), storedCreds.Salt, 1, 64*1024, 4, 32)
	if !reflect.DeepEqual(key, storedCreds.Password) {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Authentication failed. Invalid username or password"))
		return NewAuthenticationFailed(errors.New("password does not match"))
	}

	return nil
}

func loadCredentials(user string) (CredentialStorageStructure, error) {
	file, err := os.Open("db/users")
	if err != nil {
		return CredentialStorageStructure{}, err
	}
	defer file.Close()

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return CredentialStorageStructure{}, nil
		}

		var creds CredentialStorageStructure
		json.Unmarshal(line, &creds)

		if creds.Username == user {
			return creds, nil
		}
	}

	return CredentialStorageStructure{},
		NewUserDoesNotExist(errors.New("user does not exist"))
}

// Store the secrets of a user in a file.
func storeUserSecrets(creds Credentials) error {
	err := getUserSecrets(creds.Username)
	if err != nil {
		switch err.(type) {
		case *os.PathError:
		default:
			return err
		}
	}

	os.MkdirAll("db", os.ModePerm)

	storeUser, err := json.Marshal(SecretStorageStructure{
		Username:   creds.Username,
		SecretList: creds.SecretList,
	})
	storeUser = append(storeUser, []byte("\n")...)
	if err != nil {
		return err
	}

	f, err := os.OpenFile("db/users", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.Write(storeUser); err != nil {
		return err
	}

	return nil
}

func getUserSecrets(user string) error {
	file, err := os.Open("db/secrets")
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}
