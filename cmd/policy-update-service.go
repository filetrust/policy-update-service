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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/basic"
	"github.com/shaj13/go-guardian/auth/strategies/bearer"
	"github.com/shaj13/go-guardian/store"
	"github.com/urfave/negroni"
	"github.com/xeipuuv/gojsonschema"
)

const (
	ok           = "ok"
	usererr      = "user_error"
	jwterr       = "jwt_error"
	jsonerr      = "json_error"
	k8sclient    = "k8s_client_error"
	configmaperr = "configmap_error"
)

var (
	tokenProcTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gw_policyupdate_tokenrequest_processing_time_millisecond",
			Help:    "Time taken to process token creation request",
			Buckets: []float64{5, 10, 100, 250, 500, 1000},
		},
	)

	tokenReqTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gw_policyupdate_tokenrequest_received_total",
			Help: "Number of token creation requests received",
		},
		[]string{"status"},
	)

	policyUpdateProcTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gw_policyupdate_updaterequest_processing_time_millisecond",
			Help:    "Time taken to process policy update request",
			Buckets: []float64{5, 10, 100, 250, 500, 1000},
		},
	)

	policyUpdateReqTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gw_policyupdate_updaterequest_received_total",
			Help: "Number of policy update requests received",
		},
		[]string{"status"},
	)

	authProcTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gw_policyupdate_authenticate_processing_time_millisecond",
			Help:    "Time taken to authenticate the request",
			Buckets: []float64{5, 10, 100, 250, 500, 1000},
		},
	)

	authReqTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gw_policyupdate_authenticate_received_total",
			Help: "Number of authenticatations received",
		},
		[]string{"status"},
	)

	listeningPort = os.Getenv("LISTENING_PORT")
	namespace     = os.Getenv("NAMESPACE")
	configmapName = os.Getenv("CONFIGMAP_NAME")
	username      = os.Getenv("USERNAME")
	password      = os.Getenv("PASSWORD")

	authenticator auth.Authenticator
	cache         store.Cache
)

func updatePolicy(w http.ResponseWriter, r *http.Request) {
	defer func(start time.Time) {
		policyUpdateProcTime.Observe(float64(time.Since(start).Milliseconds()))
	}(time.Now())

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
			msg := "Content-Type header is not application/json"
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		log.Printf("Unable to read request body: %v", err)
		http.Error(w, "Unable to read request body.", http.StatusBadRequest)
		return
	}

	if len(body) == 0 {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		log.Printf("Expected request body, but was nil")
		http.Error(w, "Request body must not be empty.", http.StatusBadRequest)
		return
	}

	validBody, errMsg := validateBody(body)

	if !validBody {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
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
		policyUpdateReqTotal.WithLabelValues(k8sclient).Inc()
		log.Printf("Unable to get client: %v", err)
		http.Error(w, "Something went wrong getting K8 Client.", http.StatusInternalServerError)
		return
	}

	err = args.UpdatePolicy()
	if err != nil {
		policyUpdateReqTotal.WithLabelValues(configmaperr).Inc()
		log.Printf("Unable to update policy: %v", err)
		http.Error(w, "Something went wrong when updating the config map.", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Successfully updated config map."))
	policyUpdateReqTotal.WithLabelValues(ok).Inc()
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
	defer func(start time.Time) {
		tokenProcTime.Observe(float64(time.Since(start).Milliseconds()))
	}(time.Now())

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "auth-app",
		"sub": username,
		"aud": "any",
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})
	jwtToken, _ := token.SignedString([]byte("secret"))
	w.Write([]byte(jwtToken))
	tokenReqTotal.WithLabelValues(ok).Inc()
}

func validateUser(ctx context.Context, r *http.Request, usr, pass string) (auth.Info, error) {
	if usr == username && pass == password {
		return auth.NewDefaultUser(usr, "1", nil, nil), nil
	}

	authReqTotal.WithLabelValues(usererr).Inc()
	return nil, fmt.Errorf("Invalid credentials")
}

func verifyToken(ctx context.Context, r *http.Request, tokenString string) (auth.Info, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			authReqTotal.WithLabelValues(jwterr).Inc()
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	if err != nil {
		authReqTotal.WithLabelValues(jwterr).Inc()
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user := auth.NewDefaultUser(claims["sub"].(string), "", nil, nil)
		return user, nil
	}

	authReqTotal.WithLabelValues(jwterr).Inc()
	return nil, fmt.Errorf("Invalid token")
}

func authMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func(start time.Time) {
		authProcTime.Observe(float64(time.Since(start).Milliseconds()))
	}(time.Now())

	log.Println("Executing Auth Middleware")
	user, err := authenticator.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	authReqTotal.WithLabelValues(ok).Inc()
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
