package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/yookoala/middleauth"
	gormstorage "github.com/yookoala/middleauth/storage/gorm"
	"gopkg.in/jose.v1/crypto"
)

func main() {

	db := getDB()
	// environment details that are not important for now.
	host, port, cookieName, publicURL, jwtKey := varFromEnv()

	app := http.NewServeMux()
	app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := middleauth.GetUser(r.Context())
		w.Header().Add("Content-Type", "text/html;charset=utf-8")
		if user != nil {
			fmt.Fprintf(w, `Hello <a href="mailto:%s">%s</a>. You may <a href="/logout">logout here</a>`, user.PrimaryEmail, user.Name)
		} else {
			fmt.Fprintf(w, `You have not login. Please <a href="/login">login here</a>.`)
		}
	})

	// outer mux
	mux := http.NewServeMux()

	// handles the common paths:
	// 1. login page
	// 2. login redirect and callback for OAuth2 / OAuth1.0a
	middleauth.CommonHandler(
		mux,
		middleauth.EnvProviders(os.Getenv),
		gormstorage.UserStorageCallback(db),
		middleauth.JWTSession(cookieName, jwtKey, crypto.SigningMethodHS256),
		cookieName,
		publicURL,
		"/login",
		"/login/oauth2",
		"/logout",
		publicURL,
		publicURL+"/error",
	)

	// serve the app at root, if not within the login path
	mux.Handle("/", middleauth.SessionMiddleware(
		middleauth.JWTSessionDecoder(cookieName, jwtKey, crypto.SigningMethodHS256),
		gormstorage.RetrieveUser(db),
	)(app))

	log.Printf("Listening: http://" + host + ":" + port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}
