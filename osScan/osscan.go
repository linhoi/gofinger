package main

import (
	"gofinger"
	"log"
)


func main(){
	//gofinger.StoreOsScanData("00:00:00:00:00:00:00","0.0.0.0","TestOS","TestDevice")
	//go run main.go -si ens37 -u root -p qwertyuiop -h localhost -db fingerprint
	log.Println("OsScan is Running")
	gofinger.OsScanTrigger()
}
