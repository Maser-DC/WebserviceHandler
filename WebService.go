package interfaces

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	Usecase "github.com/Maser-DC/Application-Usecase"
	Domain "github.com/Psinobious/Maser-DC/Domain"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}
type WebServiceHandler struct {
	ActivityInteractor *Usecase.ActivityInteractor
	UserInteractor     *Usecase.UserInteractor
}
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func (handler WebServiceHandler) Register(w http.ResponseWriter, r *http.Request) {
	var form Domain.Client
	json.NewDecoder(r.Body).Decode(&form)

	err := handler.UserInteractor.CreateUser(form.ClientID, form.FirstName, form.LastName, form.Email, form.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}
func (handler WebServiceHandler) Login(w http.ResponseWriter, r *http.Request) {
	var cred Credentials

	err := json.NewDecoder(r.Body).Decode(&cred)

	user, err := handler.UserInteractor.FindUser(cred.Username)

	if cred.Username != user.ClientID {
		w.WriteHeader(http.StatusBadRequest)
	}

	expirationTime := time.Now().Add(10 * time.Minute)

	claims := &Claims{
		Username: cred.Username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
func (handler WebServiceHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenString := cookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	newtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newTokenString, err := newtoken.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   newTokenString,
		Expires: expirationTime,
	})
}
func (handler WebServiceHandler) Home(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("hello")

}
func (handler WebServiceHandler) ReceiveFile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("File Upload Endpoint Hit")

	// Parse our multipart form, 10 << 20 specifies a maximum
	// upload of 10 MB files.
	r.ParseMultipartForm(10 << 20)
	// FormFile returns the first file for the given key `myFile`
	// it also returns the FileHeader so we can get the Filename,
	// the Header and the size of the file
	file, filehandler, err := r.FormFile("myFile")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}
	defer file.Close()
	fmt.Printf("Uploaded File: %+v\n", filehandler.Filename)
	fmt.Printf("File Size: %+v\n", filehandler.Size)
	fmt.Printf("MIME Header: %+v\n", filehandler.Header)

	tempFile, err := ioutil.TempFile("temp-files", "*-"+filehandler.Filename)
	if err != nil {
		fmt.Println(err)
	}
	//defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}
	tempFile.Write(fileBytes)

	fmt.Fprintf(w, "Successfully Uploaded File\n")
}

func (handler WebServiceHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {

}
func (handler WebServiceHandler) CreateActivity(w http.ResponseWriter, r *http.Request) {

}
func (handler WebServiceHandler) DeleteActivity(w http.ResponseWriter, r *http.Request) {

}
func (handler WebServiceHandler) ConnectToActivity(w http.ResponseWriter, r *http.Request) {

}
func (handler WebServiceHandler) DisconnectFromActivity(w http.ResponseWriter, r *http.Request) {

}
func (handler WebServiceHandler) UploadToActivity(w http.ResponseWriter, r *http.Request) {

}
func (handler WebServiceHandler) RemoveFromActivity(w http.ResponseWriter, r *http.Request) {

}
