package gofinger

import (
	"database/sql"
	"flag"
	_ "github.com/go-sql-driver/mysql"
	"image/gif"
	"log"
)

var (
	sqlUserFlag = flag.String("u", "root", "mysql user")
	sqlPwdFlag  = flag.String("p", "qwertyuiop", "password for mysql user")
	sqlhostFlag = flag.String("h", "localhost", "host of mysql server")
	sqldbFlag   = flag.String("db", "fingerprint", "database to be used")
)

func checkErr(err error) {
	if err != nil {
		log.Println("[Mysql：Ignore]", err)
	}
}

//Create the table named "osscan" only once
//if the table exist, get scannedMac data from mysql db
func init() {
	flag.Parse()
	root := *sqlUserFlag
	pwd := *sqlPwdFlag
	host := *sqlhostFlag
	db := *sqldbFlag
	//be careful, err may be "nil"  all the time if you just call the Open() func and do nothing else
	conn, err := sql.Open("mysql", root+":"+pwd+"@tcp("+host+":3306)/"+db+"?charset=utf8")
	checkErr(err)
	defer conn.Close()

	sql := "create table osscan(" +
		"mac char(17) not null ," +
		"ip char(15)," +
		"vendor varchar(255), " +
		"osType varchar(255), " +
		"deviceType varchar(255)," +
		"openPorts varchar(255), " +
		"scanTime varchar(255)," +
		"scanDuration varchar(255)," +
		"primary key (mac))engine=innodb"
	_, _ = conn.Exec(sql)

	rows, err := conn.Query("select mac from osscan")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		var mac string
		err = rows.Scan(&mac)
		checkErr(err)
		scannedMac[mac] = true
	}

}

func StoreOsScanData(device Device) {
	flag.Parse()
	root := *sqlUserFlag
	host := *sqlhostFlag
	pwd := *sqlPwdFlag
	db := *sqldbFlag
	dataBase, err := sql.Open("mysql", root+":"+pwd+"@tcp("+host+":3306)/"+db+"?charset=utf8")
	checkErr(err)
	defer dataBase.Close()

	_, err = dataBase.Exec("insert osscan(mac,ip,vendor,osType,deviceType,openPorts,scanTime,scanDuration) value(?,?,?,?,?,?,?,?)",
		device.Mac, device.IP, device.Vendor, device.OsType, device.DeviceType, device.OpenPorts,device.ScanTime,device.ScanDuration)
	checkErr(err)

}

func ConnectToMysql() (*sql.DB, error) {
	flag.Parse()
	root := *sqlUserFlag
	host := *sqlhostFlag
	pwd := *sqlPwdFlag
	db := *sqldbFlag
	dataBase, err := sql.Open("mysql", root+":"+pwd+"@tcp("+host+":3306)/"+db+"?charset=utf8")
	return dataBase, err
}

func StoreDhcpFingerPrint(dhcpFP DhcpFP) error {
	mysql ,err := ConnectToMysql()
	if err != nil {
		return err
	}
	sql := "insert into dhcpFingerPrint(client,mac,hostName,vendor,optionList,option55List) value(?,?,?,?,?,?)"
	stmt, err := mysql.Prepare(sql)
	if err != nil {
		return err
	}
	_, err =stmt.Exec(dhcpFP.Client,dhcpFP.Mac,dhcpFP.HostName,dhcpFP.Vendor,dhcpFP.OptionList,dhcpFP.Option55List)
	return err

}

func CreateTableDhcpFP() error {
	mysql, err := ConnectToMysql()
	if err != nil {
		return err
	}
	sql := "create table dhcpFP(" +
		"client char(20) not null ," +
		"mac char(20)," +
		"hostName varchar(255), " +
		"vendor varchar(255), " +
		"optionList varchar(255)," +
		"option55List varchar(255), " +
		"primary key (client))engine=innodb"

	_, err = mysql.Exec(sql)
	return err
}

//TODO create table httpFP
