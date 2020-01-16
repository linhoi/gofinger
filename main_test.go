package gofinger

import (
	"testing"
)

func TestScanFromFile(t *testing.T){
	err := OsScanFromFile("./tutorial/ipList")
	if err != nil {
		t.Error(err.Error())
	}

}
