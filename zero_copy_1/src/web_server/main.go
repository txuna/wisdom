package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Hello")
		resp := map[string]string{"result": "Hello"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

		fmt.Println("bye")
	})

	http.ListenAndServe(":8000", nil)
}
