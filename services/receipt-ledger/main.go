package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"kronyx/pkg/ids"
	"kronyx/pkg/receipts"
)

func main() {
	ledger := receipts.NewFileLedger("/tmp/kronyx-receipts.log")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/receipts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in receipts.Receipt
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.RequestHash == "" || in.TokenID == "" || in.Summary == "" {
			http.Error(w, "missing required receipt fields", http.StatusBadRequest)
			return
		}
		in.ReceiptID = ids.New()
		in.Timestamp = time.Now().UTC()
		out, err := ledger.Append(in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	log.Fatal(http.ListenAndServe(":8084", mux))
}
