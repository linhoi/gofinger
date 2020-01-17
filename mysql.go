package gofinger

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
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
	if err := CreateTableOsscan(); err != nil {
		log.Println(err)
	}
	if err := QueryTableOsscan(); err != nil {
		log.Println(err)
	}
	if err := CreateTableDhcpFP(); err != nil {
		log.Println(err)
	}
	if err := CreateTableHttpFP(); err != nil{
		log.Println(err)
	}
}

func CreateTableOsscan() error {
	mysql , err := ConnectToMysql()
	if err != nil {
		return err
	}
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

	_, err = mysql.Exec(sql)
	return err
}
func QueryTableOsscan() error {
	mysql , err := ConnectToMysql()
	if err != nil {
		return err
	}

	rows, err := mysql.Query("select mac from osscan")
	if err != nil {
		return err
	}

	for rows.Next() {
		var mac string
		err = rows.Scan(&mac)
		if err != nil {
			return err
		}
		scannedMac[mac] = true
	}
	return nil
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

	_, err = dataBase.Exec("insert into osscan(mac,ip,vendor,osType,deviceType,openPorts,scanTime,scanDuration) values(?,?,?,?,?,?,?,?)",
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

func StoreDhcpFP(dhcpFP DhcpFP) error {
	mysql ,err := ConnectToMysql()
	if err != nil {
		return err
	}
	sql := "insert into dhcpFP(client,mac,hostName,vendor,optionList,option55List) values(?,?,?,?,?,?)"
	optionList := fmt.Sprintf("%v",dhcpFP.OptionList)
	option55List := fmt.Sprintf("%v",dhcpFP.Option55List)
	_, err =mysql.Exec(sql,dhcpFP.Client,dhcpFP.Mac,dhcpFP.HostName,dhcpFP.Vendor,optionList,option55List)
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
		"primary key (mac))engine=innodb"

	_, err = mysql.Exec(sql)
	return err
}

//TODO create table httpFP
func StoreHttpFP(httpFp HttpFP) error {
	mysql ,err := ConnectToMysql()
	if err != nil {
		return err
	}
	sql := "insert into httpFP(ip,mac,host,userAgent,cookie,os) values(?,?,?,?,?,?)"
	stmt, err := mysql.Prepare(sql)
	if err != nil {
		return err
	}
	_, err =stmt.Exec(httpFp.Ip,httpFp.Mac,httpFp.Host,httpFp.UserAgent,httpFp.Cookie,httpFp.OS)
	return err

}
func CreateTableHttpFP() error {
	mysql, err := ConnectToMysql()
	if err != nil {
		return err
	}
	sql := "create table httpFP(" +
		"ip char(20) not null ," +
		"mac char(20)," +
		"host varchar(255), " +
		"userAgent varchar(255), " +
		"cookie varchar(255)," +
		"os varchar(255), " +
		"primary key (mac))engine=innodb"

	_, err = mysql.Exec(sql)
	return err
}
