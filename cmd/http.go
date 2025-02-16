package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/oarkflow/crypto" // Import your crypto package here.
)

// response is a common structure for JSON responses.
type response struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func jsonResponse(w http.ResponseWriter, res response) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// ---------------- API Endpoints ----------------

// Generate CA certificate endpoint
func genCAHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.CAParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.GenerateCAWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "CA certificate generated."})
}

// Generate Server certificate endpoint
func genServerHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.ServerParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.GenerateServerWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Server certificate generated."})
}

// Generate Client certificate endpoint
func genClientHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.ClientParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.GenerateClientWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Client certificate generated."})
}

// Generate Code Signing certificate endpoint
func genCodeSignHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CACertFile string `json:"CACertFile"`
		CAKeyFile  string `json:"CAKeyFile"`
		CommonName string `json:"CommonName"`
		RsaBits    string `json:"RsaBits"`
		CertOut    string `json:"CertOut"`
		KeyOut     string `json:"KeyOut"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rsaBits, err := strconv.Atoi(input.RsaBits)
	if err != nil {
		jsonResponse(w, response{Status: "error", Error: "Invalid RSA bits value."})
		return
	}
	params := crypto.CodeSignParams{
		CACertFile: input.CACertFile,
		CAKeyFile:  input.CAKeyFile,
		CommonName: input.CommonName,
		RsaBits:    rsaBits,
		CertOut:    input.CertOut,
		KeyOut:     input.KeyOut,
	}
	if err := crypto.GenerateCodeSignWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Code-signing certificate generated."})
}

// Generate CRL endpoint
func genCRLHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CACertFile string `json:"CACertFile"`
		CAKeyFile  string `json:"CAKeyFile"`
		Revoked    string `json:"Revoked"`
		CRLOut     string `json:"CRLOut"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	params := crypto.CRLParams{
		CACertFile: input.CACertFile,
		CAKeyFile:  input.CAKeyFile,
		Revoked:    input.Revoked,
		CRLOut:     input.CRLOut,
	}
	if err := crypto.GenerateCRLWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "CRL generated."})
}

// Verify CRL endpoint
func verifyCRLHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CertFile string `json:"CertFile"`
		CRLFile  string `json:"CRLFile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.CertFile == "" || input.CRLFile == "" {
		jsonResponse(w, response{Status: "error", Error: "Both CertFile and CRLFile are required."})
		return
	}
	if err := crypto.VerifyCertificateRevocationStatus(input.CertFile, input.CRLFile); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Certificate is not revoked."})
}

// Sign file endpoint
func signHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.SignParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.SignFileWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "File signed successfully."})
}

// Verify file signature endpoint
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.VerifyParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.VerifyFileSignatureWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "File signature verified successfully."})
}

// Sign text endpoint
func signTextHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.SignTextParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.SignTextWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Text signed successfully."})
}

// Verify text signature endpoint
func verifyTextHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.VerifyTextParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.VerifyTextWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Text signature verified successfully."})
}

// Sign JSON endpoint
func signJSONHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.SignJSONParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.SignJSONWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "JSON signed successfully."})
}

// Verify JSON signature endpoint
func verifyJSONHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.VerifyJSONParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.VerifyJSONWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "JSON signature verified successfully."})
}

// Inspect certificate endpoint
func inspectHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CertFile string `json:"CertFile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// In a full implementation, you might capture detailed inspection info.
	output := fmt.Sprintf("Inspection details for certificate: %s", input.CertFile)
	jsonResponse(w, response{Status: "success", Data: output})
}

// List certificates endpoint
func listCertsHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Files string `json:"Files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.Files == "" {
		jsonResponse(w, response{Status: "error", Error: "Please provide certificate file names."})
		return
	}
	files := strings.Split(input.Files, ",")
	var details []string
	for _, f := range files {
		f = strings.TrimSpace(f)
		details = append(details, fmt.Sprintf("Details for certificate %s", f))
	}
	jsonResponse(w, response{Status: "success", Data: details})
}

// Validate client certificate against a CA endpoint
func validateHandler(w http.ResponseWriter, r *http.Request) {
	var params crypto.ValidateParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := crypto.ValidateClientCertificateWithParams(params); err != nil {
		jsonResponse(w, response{Status: "error", Error: err.Error()})
		return
	}
	jsonResponse(w, response{Status: "success", Data: "Client certificate validated successfully."})
}

// ---------------- Main ----------------

func main() {
	// Register API endpoints.
	http.HandleFunc("/api/gen-ca", genCAHandler)
	http.HandleFunc("/api/gen-server", genServerHandler)
	http.HandleFunc("/api/gen-client", genClientHandler)
	http.HandleFunc("/api/gen-code-sign", genCodeSignHandler)
	http.HandleFunc("/api/gen-crl", genCRLHandler)
	http.HandleFunc("/api/verify-crl", verifyCRLHandler)
	http.HandleFunc("/api/sign", signHandler)
	http.HandleFunc("/api/verify", verifyHandler)
	http.HandleFunc("/api/sign-text", signTextHandler)
	http.HandleFunc("/api/verify-text", verifyTextHandler)
	http.HandleFunc("/api/sign-json", signJSONHandler)
	http.HandleFunc("/api/verify-json", verifyJSONHandler)
	http.HandleFunc("/api/inspect", inspectHandler)
	http.HandleFunc("/api/list-certs", listCertsHandler)
	http.HandleFunc("/api/validate", validateHandler)

	// Serve static files (HTML, CSS, JS) from the "static" folder.
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	fmt.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
