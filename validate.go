package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
)

func validateEmail(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	email := string(b)
	err = validate.Var(email, "required,max=255,email")
	if err != nil {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}
	count, err := users.CountDocuments(context.TODO(), bson.M{"email": email})
	if err != nil {
		log.Println(err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	if count != 0 {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(10000))
	code := int(nBig.Int64())

	message := mg.NewMessage("Meny <noreply@meny.wiren.cc>", "Verifieringskod från Meny", "", email)
	message.SetHtml(fmt.Sprintf("<p><b>%04d</b> är din verifieringskod för Meny.</p><p>Hälsningar,<br>Meny</p>", code))
	_, _, err = mg.Send(context.TODO(), message)
	if err != nil {
		log.Println(err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(*secret))

	// Write Data to it
	h.Write([]byte{byte(code)})

	// Get result and encode as hexadecimal string
	codeHash := hex.EncodeToString(h.Sum(nil))

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"code":  codeHash,
		"exp":   time.Now().Add(time.Minute * 5),
		"iat":   time.Now(),
	})
	tokenString, _ := token.SignedString([]byte(*secret))
	w.Write([]byte(tokenString))
}
