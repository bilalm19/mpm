package main

import "mpm/server"

func main() {
	mpmServer := server.New()
	// go mpmServer.StartEdgeServer()

	// err := client.Login(2)
	// // err := client.SignUp()
	// if err != nil {
	// 	logger.Fatal(err)
	// }
	mpmServer.StartEdgeServer()
}
