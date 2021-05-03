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

	"golang.org/x/crypto/argon2"
)

// respondClient send back response to client along with the http status code.
func respondClient(writer http.ResponseWriter, code int, resp []byte) {
	writer.WriteHeader(code)
	writer.Write(resp)
}

func decodeClientMessage(body io.ReadCloser, writer http.ResponseWriter) (credentials, error) {
	decoder := json.NewDecoder(body)
	var creds credentials
	err := decoder.Decode(&creds)
	if err != nil {
		logger.Error(err)
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("500 Server Error"))
		return creds, err
	}

	return creds, nil
}

func storeCredentials(creds credentials) error {
	randNum := rand.Uint32()
	salt := make([]byte, 4)
	binary.LittleEndian.PutUint32(salt, randNum)
	key := argon2.IDKey([]byte(creds.Password), salt, 1, 64*1024, 4, 32)

	os.MkdirAll("db", os.ModePerm)

	storeUser, err := json.Marshal(credentialStorageStructure{
		Username: creds.Username,
		Password: key,
		Salt:     salt,
	})
	storeUser = append(storeUser, []byte("\n")...)
	if err != nil {
		return err
	}

	if err = writeToDatabase("db/users", storeUser); err != nil {
		return err
	}

	return nil
}

func verifyLogin(creds credentials, writer http.ResponseWriter) error {
	storedCreds, err := loadCredentials(creds.Username)
	if err != nil {
		switch err.(type) {
		case *UserDoesNotExist:
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Authentication failed. Invalid username or password"))
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

func loadCredentials(user string) (credentialStorageStructure, error) {
	file, err := os.Open("db/users")
	if err != nil {
		return credentialStorageStructure{}, err
	}
	defer file.Close()

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return credentialStorageStructure{}, err
		}

		var creds credentialStorageStructure
		json.Unmarshal(line, &creds)

		if creds.Username == user {
			return creds, nil
		}
	}

	return credentialStorageStructure{},
		NewUserDoesNotExist(errors.New("user does not exist"))
}

// Store the secrets of a user in a file.
func storeUserSecrets(creds credentials) error {
	hasSecrets := true
	secrets, err := getUserSecrets(creds.Username)
	var secretStorage secretStorageStructure
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			secretStorage.Username = creds.Username
			if secretStorage.SecretList, err = encryptMap([]byte(creds.Password), creds.SecretList); err != nil {
				return err
			}
			hasSecrets = false
		case *NoSecrets:
			secretStorage.Username = creds.Username
			if secretStorage.SecretList, err = encryptMap([]byte(creds.Password), creds.SecretList); err != nil {
				return err
			}
			hasSecrets = false
		default:
			return err
		}
	} else {
		secretStorage = secrets
		for k, v := range creds.SecretList {
			// Do not re-encrypt the values that have already been added to the
			// database.
			if _, ok := secretStorage.SecretList[k]; !ok {
				ciphertext, err := encryptaesgcm([]byte(creds.Password), []byte(v))
				if err != nil {
					return err
				}
				secretStorage.SecretList[k] = ciphertext
			}
		}
	}

	os.MkdirAll("db", os.ModePerm)

	mstoreSecrets, err := json.Marshal(secretStorage)
	mstoreSecrets = append(mstoreSecrets, []byte("\n")...)
	if err != nil {
		return err
	}

	if err = updateSecretsDatabase(creds.Username, mstoreSecrets, hasSecrets); err != nil {
		return err
	}

	return nil
}

func getUserSecrets(user string) (secretStorageStructure, error) {
	file, err := os.Open("db/secrets")
	if err != nil {
		return secretStorageStructure{}, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes(10)
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return secretStorageStructure{}, err
		}

		var secrets secretStorageStructure
		json.Unmarshal(line, &secrets)

		if secrets.Username == user {
			return secrets, nil
		}
	}

	return secretStorageStructure{}, NewNoSecrets(errors.New("user has no secrets"))
}

func updateSecretsDatabase(user string, data []byte, hasSecrets bool) error {
	var database []byte

	file, err := os.Open("db/secrets")
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			database = data
			hasSecrets = true
		default:
			return err
		}
	} else {
		defer file.Close()

		reader := bufio.NewReader(file)
		for {
			line, err := reader.ReadBytes(10)
			if err != nil && err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			var secrets secretStorageStructure
			json.Unmarshal(line, &secrets)

			if secrets.Username == user {
				database = append(database, data...)
			} else {
				database = append(database, line...)
			}
		}
	}

	if !hasSecrets {
		database = append(database, data...)
	}

	if err = writeToDatabase("db/secrets", database); err != nil {
		return err
	}

	return nil
}

// writeToDatabase create or open the database file and
func writeToDatabase(filename string, data []byte) error {
	var f *os.File
	var err error

	if filename == "db/users" {
		f, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	} else if filename == "db/secrets" {
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	} else {
		err = errors.New("unknown database")
	}

	if err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}

	return nil
}
