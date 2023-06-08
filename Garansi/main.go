package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db            *sql.DB
	store         *sessions.CookieStore
	tmpl          *template.Template
	sessionName   = "session-name"
	sessionSecret = "session-secret"
)

type User struct {
	ID       int
	Name     string
	Username string
	Email    string
	Password string
}

type Warranty struct {
	ID      int
	UserID  int
	Item    string
	Details string
}

func main() {
	// Koneksi ke database
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=try dbname=garansi sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Inisialisasi cookie store
	store = sessions.NewCookieStore([]byte(sessionSecret))

	// Compile template HTML
	tmpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	// Routing
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/register", registerHandler)
	r.HandleFunc("/forgot", forgotPasswordHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/warranty", warrantyHandler)
	r.HandleFunc("/profile", profileHandler)
	r.HandleFunc("/add-warranty", addWarrantyHandler)
	r.HandleFunc("/edit-warranty/{id}", editWarrantyHandler).Methods("GET", "POST")
	r.HandleFunc("/delete-warranty/{id}", deleteWarrantyHandler).Methods("POST")
	http.Handle("/", r)

	// Jalankan server pada port 8080
	log.Println("Server started on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Ambil user ID dari session
	session, err := store.Get(r, sessionName)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Ambil data garansi berdasarkan user ID
	warranties, err := getWarrantiesByUserID(userID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render halaman home dengan data garansi
	tmpl.ExecuteTemplate(w, "home.html", warranties)
}

func warrantyHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Ambil user ID dari session
	session, err := store.Get(r, sessionName)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Ambil data garansi berdasarkan user ID
	warranties, err := getWarrantiesByUserID(userID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render halaman data garansi
	tmpl.ExecuteTemplate(w, "warranty.html", warranties)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Render halaman profile
	tmpl.ExecuteTemplate(w, "profile.html", nil)
}

func addWarrantyHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Ambil data form
		item := r.FormValue("item")
		details := r.FormValue("details")

		// Ambil user ID dari session
		session, err := store.Get(r, sessionName)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		userID, ok := session.Values["user_id"].(int)
		if !ok {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Simpan data garansi ke database
		err = createWarranty(userID, item, details)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirect ke halaman data garansi
		http.Redirect(w, r, "/warranty", http.StatusSeeOther)
		return
	}

	// Render halaman tambah garansi
	tmpl.ExecuteTemplate(w, "add_warranty.html", nil)
}

func editWarrantyHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Ambil ID garansi dari URL
	vars := mux.Vars(r)
	id := vars["id"]

	// Ambil data garansi berdasarkan ID
	warranty, err := getWarrantyByID(id)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if warranty == nil {
		http.NotFound(w, r)
		return
	}

	if r.Method == "POST" {
		// Ambil data form
		item := r.FormValue("item")
		details := r.FormValue("details")

		// Perbarui data garansi ke database
		err := updateWarranty(warranty.ID, item, details)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirect ke halaman data garansi
		http.Redirect(w, r, "/warranty", http.StatusSeeOther)
		return
	}

	// Render halaman edit garansi
	tmpl.ExecuteTemplate(w, "edit_warranty.html", warranty)
}

func deleteWarrantyHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Ambil ID garansi dari URL
	vars := mux.Vars(r)
	id := vars["id"]

	// Hapus data garansi dari database
	err := deleteWarranty(id)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect ke halaman data garansi
	http.Redirect(w, r, "/warranty", http.StatusSeeOther)
}

func isLoggedIn(r *http.Request) bool {
	session, err := store.Get(r, sessionName)
	if err != nil {
		return false
	}

	_, ok := session.Values["user_id"].(int)
	return ok
}

func createWarranty(userID int, item, details string) error {
	_, err := db.Exec("INSERT INTO warranty (user_id, item, details) VALUES ($1, $2, $3)", userID, item, details)
	return err
}

func getWarrantiesByUserID(userID int) ([]Warranty, error) {
	rows, err := db.Query("SELECT id, user_id, item, details FROM warranty WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var warranties []Warranty
	for rows.Next() {
		var warranty Warranty
		err := rows.Scan(&warranty.ID, &warranty.UserID, &warranty.Item, &warranty.Details)
		if err != nil {
			return nil, err
		}
		warranties = append(warranties, warranty)
	}

	return warranties, nil
}

func getWarrantyByID(id string) (*Warranty, error) {
	var warranty Warranty
	err := db.QueryRow("SELECT id, user_id, item, details FROM warranty WHERE id = $1", id).Scan(&warranty.ID, &warranty.UserID, &warranty.Item, &warranty.Details)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &warranty, nil
}

func updateWarranty(id int, item, details string) error {
	_, err := db.Exec("UPDATE warranty SET item = $1, details = $2 WHERE id = $3", item, details, id)
	return err
}

func deleteWarranty(id string) error {
	_, err := db.Exec("DELETE FROM warranty WHERE id = $1", id)
	return err
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Ambil data form
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Periksa kecocokan username dan password di database
		user, err := getUserByUsername(username)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if user == nil || !checkPasswordHash(password, user.Password) {
			// Login gagal
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Buat session baru
		session, err := store.Get(r, sessionName)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		session.Values["user_id"] = user.ID
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirect ke halaman utama setelah login berhasil
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Render halaman login
	tmpl.ExecuteTemplate(w, "login.html", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Ambil data form
		name := r.FormValue("name")
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		agree := r.FormValue("agree")

		// Cek persetujuan syarat dan ketentuan
		if agree != "on" {
			http.Error(w, "Anda harus menyetujui syarat dan ketentuan", http.StatusBadRequest)
			return
		}

		// Enkripsi password
		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Simpan data user ke database
		err = createUser(name, username, email, hashedPassword)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirect ke halaman login setelah registrasi berhasil
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Render halaman registrasi
	tmpl.ExecuteTemplate(w, "register.html", nil)
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Cek status login
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Ambil data form
		usernameOrEmail := r.FormValue("username_or_email")

		// Cek apakah username atau email terdapat dalam database
		user, err := getUserByUsernameOrEmail(usernameOrEmail)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if user == nil {
			// Username atau email tidak ditemukan
			http.Redirect(w, r, "/forgot", http.StatusSeeOther)
			return
		}

		// Tampilkan pesan "Akun ditemukan"
		fmt.Fprintln(w, "Akun ditemukan")
		return
	}

	// Render halaman lupa password
	tmpl.ExecuteTemplate(w, "forgot.html", nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Hapus session
	session, err := store.Get(r, sessionName)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect ke halaman login setelah logout
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func createUser(name, username, email, password string) error {
	_, err := db.Exec("INSERT INTO users (name, username, email, password) VALUES ($1, $2, $3, $4)", name, username, email, password)
	return err
}

func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, name, username, email, password FROM users WHERE username = $1", username).Scan(&user.ID, &user.Name, &user.Username, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func getUserByUsernameOrEmail(usernameOrEmail string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, name, username, email, password FROM users WHERE username = $1 OR email = $1", usernameOrEmail).Scan(&user.ID, &user.Name, &user.Username, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}
