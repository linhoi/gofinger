package gofinger

import (
	"database/sql"
	"flag"
	_ "github.com/go-sql-driver/mysql"
	"log"
)
var(
	sqlUserFlag = flag.String("u","root","mysql user")
	sqlPwdFlag  = flag.String("p","qwertyuiop","password for mysql user")
	sqlhostFlag = flag.String("h","localhost","host of mysql server")
	sqldbFlag   = flag.String("db","fingerprint","database to be used")

)

func checkErr(err error){
	if err != nil {
		log.Println("[Mysql：Ignore]",err)
	}
}

//Create the table named "osscan" only once
//if the table exist, get scannedMac data from mysql db
func init(){
	flag.Parse()
	root  := *sqlUserFlag
	pwd   := *sqlPwdFlag
	host  := *sqlhostFlag
	db    := *sqldbFlag
	//be careful, err may be "nil"  all the time if you just call the Open() func and do nothing else
	conn, err := sql.Open("mysql", root + ":" + pwd +"@tcp("+host+":3306)/"+db+"?charset=utf8")
	checkErr(err)
	defer conn.Close()

	_, err = conn.Exec("create table osscan(" + "mac char(17) not null ,ip char(15),vendor varchar(255), osType varchar(255), deviceType varchar(255),openPorts varchar(255), primary key (mac))engine=innodb")
	checkErr(err)

	rows, err := conn.Query("select mac from osscan")
	if err != nil {
		panic(err)
	}

	for rows.Next(){
		var mac string
		err = rows.Scan(&mac)
		checkErr(err)
		scannedMac[mac] = true
	}

}


func StoreOsScanData(device Device) {
	flag.Parse()
	root 	  := *sqlUserFlag
	host  	  := *sqlhostFlag
	pwd 	  := *sqlPwdFlag
	db        := *sqldbFlag
	conn, err := sql.Open("mysql", root + ":" + pwd +"@tcp("+host+":3306)/"+db+"?charset=utf8")
	checkErr(err)
	defer conn.Close()

	_, err= conn.Exec("insert osscan(mac,ip,vendor,osType,deviceType,openPorts) value(?,?,?,?,?,?)",
		device.Mac,device.IP,device.Vendor,device.OsType,device.DeviceType,device.OpenPorts)
	checkErr(err)

}

