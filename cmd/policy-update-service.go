package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/filetrust/policy-update-service/pkg"
	"github.com/gorilla/mux"
)

var (
	listeningPort = os.Getenv("LISTENING_PORT")
	namespace     = os.Getenv("NAMESPACE")
	configmapName = os.Getenv("CONFIGMAP_NAME")
)

func updatePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Unable to read request body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Unable to read request body."))
		return
	}

	if len(body) == 0 {
		log.Printf("Expected request body, but was nil")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Request body must not be empty."))
		return
	}

	args := policy.PolicyArgs{
		Policy:        string(body),
		Namespace:     namespace,
		ConfigMapName: configmapName,
	}

	err = args.GetClient()
	if err != nil {
		log.Printf("Unable to get client: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Something went wrong getting K8 Client."))
		return
	}

	err = args.UpdatePolicy()
	if err != nil {
		log.Printf("Unable to update policy: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Something went wrong when updating the config map."))
		return
	}
}

func handleRequests() {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/policy", updatePolicy).Methods("PUT")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", listeningPort), router))
}

func main() {
	if listeningPort == "" || namespace == "" || configmapName == "" {
		log.Fatalf("init failed: LISTENTING_PORT, NAMESPACE, or CONFIGMAP_NAME environment variables not set")
	}

	log.Printf("Listening on port :%v", listeningPort)

	handleRequests()
}
