package main

import (
	"github.com/google/uuid"
	"html/template"
	"log"
	"net/http"
	"time"
)

var users = map[string]Credentials{"admin": {"admin", "test@example.com", "root"}}

var sessions = map[string]session{}

type session struct {
	username string
	expiry   time.Time
}

type Credentials struct {
	Username string
	Email    string
	Password string
}

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/refresh", refresh)
	http.HandleFunc("/welcome", welcome)
	http.HandleFunc("/loginRequest", loginRequest)
	http.HandleFunc("/profile", profile)
	http.HandleFunc("/signupHandler", signupHandler)
	http.HandleFunc("/logout", logout)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
func login(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "html/Login.html")

}

func signup(w http.ResponseWriter, r *http.Request) {

	http.ServeFile(w, r, "html/SignUp.html")
}
func signupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	creds := Credentials{
		username, email, password,
	}

	for user, data := range users {
		if user == username || data.Email == email {
			http.Redirect(w, r, "/signup", http.StatusFound)
			return
		}
	}
	users[username] = creds
	startSession(w, r, creds)
}

func welcome(w http.ResponseWriter, r *http.Request) {

}

func loginRequest(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")
	cred := Credentials{Username: username, Password: password}

	expectedPassword, ok := users[username]
	if !ok || cred.Password != expectedPassword.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	startSession(w, r, cred)

}

func profile(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {

			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sessionToken := cookie.Value
	userSession, exists := sessions[sessionToken]
	if !exists {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if userSession.isExpired() {
		delete(sessions, sessionToken)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	renderUser(w, users[userSession.username])
}
func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

func renderUser(w http.ResponseWriter, data Credentials) {
	tmpl := template.Must(template.ParseFiles("html/Profile.html"))
	err := tmpl.Execute(w, data)
	if err != nil {
		return
	}

}

func startSession(w http.ResponseWriter, r *http.Request, creds Credentials) {
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(30 * time.Second)

	sessions[sessionToken] = session{
		creds.Username,
		expiresAt,
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
		Path:    "/",
	})
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value
	userSession, exists := sessions[sessionToken]

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	delete(sessions, sessionToken)
	startSession(w, r, users[userSession.username])
}

func logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	delete(sessions, sessionToken)
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
	})
	http.Redirect(w, r, "/login", http.StatusFound)

}
