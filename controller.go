package gofinger

import "runtime"

// TODO control data store from redis to mysql

type Icontroller interface {
	GetDevicesDataFromRedis() []string
	ValidateDevices() (credibility map[string]float32)
	StoreDevicesDataToMysql() error
}
func test() {
	runtime.GC()
}
