package gofinger

import (
	"testing"
)

func TestScanFromFile(t *testing.T){
	err := ScanFromFile("./tutorial/ipList")
	if err != nil {
		t.Error(err.Error())
	}

}
