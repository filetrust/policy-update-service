package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	policy "github.com/filetrust/policy-update-service/pkg"
	"github.com/golang/gddo/httputil/header"
	"github.com/gorilla/mux"
	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/basic"
	"github.com/shaj13/go-guardian/auth/strategies/bearer"
	"github.com/shaj13/go-guardian/store"
	"github.com/urfave/negroni"
	"github.com/xeipuuv/gojsonschema"
)

var (
	listeningPort = os.Getenv("LISTENING_PORT")
	namespace     = os.Getenv("NAMESPACE")
	configmapName = os.Getenv("CONFIGMAP_NAME")
	username      = os.Getenv("USERNAME")
	password      = os.Getenv("PASSWORD")

	authenticator auth.Authenticator
	cache         store.Cache
)

func updatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			msg := "Content-Type header is not application/json"
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Unable to read request body: %v", err)
		http.Error(w, "Unable to read request body.", http.StatusBadRequest)
		return
	}

	if len(body) == 0 {
		log.Printf("Expected request body, but was nil")
		http.Error(w, "Request body must not be empty.", http.StatusBadRequest)
		return
	}

	validBody, errMsg := validateBody(body)

	if !validBody {
		log.Printf(errMsg)
		http.Error(w, errMsg, http.StatusBadRequest)
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
		http.Error(w, "Something went wrong getting K8 Client.", http.StatusInternalServerError)
		return
	}

	err = args.UpdatePolicy()
	if err != nil {
		log.Printf("Unable to update policy: %v", err)
		http.Error(w, "Something went wrong when updating the config map.", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Successfully updated config map."))
}

func validateBody(body []byte) (bool, string) {
	schemaLoader := gojsonschema.NewReferenceLoader("file:///bin/schema.json")
	bodyLoader := gojsonschema.NewBytesLoader(body)

	result, err := gojsonschema.Validate(schemaLoader, bodyLoader)
	if err != nil {
		return false, err.Error()
	}

	if !result.Valid() {
		errors := "The document is not valid. See errors :\n"

		for _, desc := range result.Errors() {
			errors += fmt.Sprintf("- %s\n", desc)
		}

		return false, errors
	}

	return true, ""
}

func createToken(w http.ResponseWriter, r *http.Request) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "auth-app",
		"sub": username,
		"aud": "any",
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})
	jwtToken, _ := token.SignedString([]byte("secret"))
	w.Write([]byte(jwtToken))
}

func validateUser(ctx context.Context, r *http.Request, usr, pass string) (auth.Info, error) {
	if usr == username && pass == password {
		return auth.NewDefaultUser(usr, "1", nil, nil), nil
	}

	return nil, fmt.Errorf("Invalid credentials")
}

func verifyToken(ctx context.Context, r *http.Request, tokenString string) (auth.Info, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user := auth.NewDefaultUser(claims["sub"].(string), "", nil, nil)
		return user, nil
	}

	return nil, fmt.Errorf("Invalid token")
}

func authMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Println("Executing Auth Middleware")
	user, err := authenticator.Authenticate(r)
	if err != nil {
		code := http.StatusUnauthorized
		http.Error(w, err.Error(), code)
		return
	}
	log.Printf("User %s Authenticated\n", user.UserName())
	next.ServeHTTP(w, r)
}

func setupGoGuardian() {
	authenticator = auth.New()
	cache = store.NewFIFO(context.Background(), time.Minute*10)

	basicStrategy := basic.New(validateUser, cache)
	tokenStrategy := bearer.New(verifyToken, cache)

	authenticator.EnableStrategy(basic.StrategyKey, basicStrategy)
	authenticator.EnableStrategy(bearer.CachedStrategyKey, tokenStrategy)
}

func main() {
	if listeningPort == "" || namespace == "" || configmapName == "" || username == "" || password == "" {
		log.Fatalf("init failed: LISTENTING_PORT, NAMESPACE, CONFIGMAP_NAME, USERNAME or PASSWORD environment variables not set")
	}

	log.Printf("Listening on port with TLS :%v", listeningPort)

	setupGoGuardian()
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/token", createToken).Methods("GET")
	router.HandleFunc("/api/v1/policy", updatePolicy).Methods("PUT")

	n := negroni.New()
	n.Use(negroni.NewRecovery())
	n.Use(negroni.NewLogger())
	n.Use(negroni.HandlerFunc(authMiddleware))
	n.UseHandler(router)

	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%v", listeningPort), "/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key", n))
}
