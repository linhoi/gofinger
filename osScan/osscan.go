package main

import "gofinger"

func main(){
	//gofinger.StoreOsScanData("00:00:00:00:00:00:00","0.0.0.0","TestOS","TestDevice")
	//go run main.go -si ens37 -u root -p qwertyuiop -h localhost -db fingerprint
	gofinger.OsScanTrigger()
}
