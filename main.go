package main

import (
	"mpm/logging"
	"mpm/server"
)

func main() {
	mpmServer := server.New()
	if err := mpmServer.StartEdgeServer(); err != nil {
		logging.MPMLogger.Fatal(err)
	}
}
