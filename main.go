package main

import (
	"mpm/client"
	"mpm/logger"
	"mpm/server"
)

func main() {

	mpmServer := server.New()
	go mpmServer.StartEdgeServer()

	err := client.Login(0)
	if err != nil {
		logger.Fatal(err)
	}
}
