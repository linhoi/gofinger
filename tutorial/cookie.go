package main

import (
	"io"
	"log"
	"net/http"
	"time"
)

func addCookie(w http.ResponseWriter, name , value string ){
	expire := time.Now().AddDate(0,0,1)
	cookie := http.Cookie{
		Name:       name,
		Value:      value,
		Expires:    expire,
	}

	http.SetCookie(w, &cookie)
}

func main(){
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		addCookie(w, "cookieName", "testValue")
		_, _ = io.WriteString(w, "Hello Cookie")
	})
	log.Fatal(http.ListenAndServe(":9999",nil))
}
