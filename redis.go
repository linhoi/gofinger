package gofinger

import (
	"fmt"
	"github.com/go-redis/redis/v7"
)

type IRedis interface {
	Conn() error
	StoreHttpPFInRedis(httpFP *HttpFP) error
	StoreDhcpPFInRedis(dhcpFP *DhcpFP) error
	StoreDeviceDataInRedis(device *Device ) error
	HGetAll(mac string) (map[string]string, error)
}

type RedisClient struct {
	Client *redis.Client
}

func NewRedisClientComplicate(addr,password string, db int) IRedis {
	client := redis.NewClient(&redis.Options{
		Addr:               addr,
		Password:           password,
		DB:                 db,
	})
	return &RedisClient{client}
}
func NewRedisClientSimple() IRedis {
	client := redis.NewClient(&redis.Options{
		Addr:               "localhost:6379",
		Password:           "",
		DB:                 0,
	})
	return &RedisClient{client}
}

func (r *RedisClient) Conn() error {
	client := r.Client
	_, err := client.Ping().Result()
	return err

}
func (r *RedisClient) StoreHttpPFInRedis(httpFP *HttpFP) error {
	err := r.Client.HMSet("GOMac."+httpFP.Mac,
		"http.IP",httpFP.Ip,
		"http.userAgent", httpFP.UserAgent,
		"http.cookie", httpFP.Cookie,
		"http.OS", httpFP.OS,
		).Err()
	return err
}

func (r *RedisClient)StoreDhcpPFInRedis(dhcpFP *DhcpFP) error {
	optionList := fmt.Sprintf("%v",dhcpFP.OptionList)
	option55List := fmt.Sprintf("%v",dhcpFP.Option55List)
	err := r.Client.HMSet("GoMac."+dhcpFP.Mac,
		"dhcp.IP", dhcpFP.Client,
		"dhcp.hostName",dhcpFP.HostName,
		"dhcp.vendor", dhcpFP.Vendor,
		"dhcp.optionList" ,optionList,
		"dhcp.option55List", option55List,
		).Err()
	return err
}

func (r *RedisClient)StoreDeviceDataInRedis(device *Device ) error {
	err := r.Client.HMSet("GoMac."+device.Mac,
		"device.vendor", device.Vendor,
		"device.IP", device.IP,
		"device.osType",device.OsType,
		"device.type",device.DeviceType,
		"device.openPorts", device.OpenPorts,
		).Err()
	return err
}

func (r *RedisClient)HGetAll(mac string) (map[string]string,error) {
	resultMap , err := r.Client.HGetAll("GoMac."+mac).Result()
	if err != nil {
		return nil, err
	}
	return resultMap, nil
}
/*
type DhcpFP struct {
	Client       string `json:"client"`
	Mac          string `json:"mac"`
	HostName     string `json:"hostName"`
	Vendor       string `json:"vendor"`
	OptionList   []byte `json:"optionList"`
	Option55List []byte `json:"option55List"`
}
type Device struct {
	Mac          string
	Vendor       string
	IP           string
	OsType       string
	DeviceType   string
	OpenPorts    string
	ScanTime     string
	ScanDuration string
}
type HttpFP struct {
	Ip        string `json:"IP"`
	Mac       string `json:"Mac"`
	Host      string `json:"Host"`
	UserAgent string `json:"UserAgent"`
	Cookie    string `json:"Cookie"`
	OS        string `json:"Os"`
}
 */