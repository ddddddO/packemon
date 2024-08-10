package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("passive!")
	fmt.Fprintf(w, "Hellll")
}

func main() {
	fmt.Println("launch server!")
	http.HandleFunc("/", handler)
	http.ListenAndServe(":80", nil)
}
