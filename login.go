package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// A User represents user data
type User struct {
	FirstName string             `json:"firstName" bson:"first_name"`
	LastName  string             `json:"lastName" bson:"last_name"`
	Email     string             `json:"email" bson:"email" validate:"required,max=255,email"`
	Password  string             `json:"password" bson:"password" validate:"required,max=255"`
	Home      primitive.ObjectID `json:"home,omitempty"`
}

// A NewUser represents a new user
type NewUser struct {
	FirstName string             `json:"firstName" bson:"first_name" validate:"required,max=255"`
	LastName  string             `json:"lastName" bson:"last_name" validate:"required,max=255"`
	Password  string             `json:"password" bson:"password" validate:"required,min=8,max=255"`
	Token     string             `json:"token" bson:"-" validate:"required"`
	Code      int                `json:"code" bson:"-" validate:"required,min=0,max=9999"`
	Email     string             `json:"-" bson:"email"`
	Home      primitive.ObjectID `json:"-" bson:"home"`
}

// A PatchUser represents user data to change
type PatchUser struct {
	Email       string `json:"-" bson:"-" validate:"omitempty,max=255,email"`
	FirstName   string `json:"firstName,omitempty" bson:"first_name,omitempty" validate:"max=255"`
	LastName    string `json:"lastName,omitempty" bson:"last_name,omitempty" validate:"max=255"`
	Password    string `json:"password,omitempty" bson:"-" validate:"max=255"`
	NewPassword string `json:"newPassword,omitempty" bson:"password,omitempty" validate:"min=8,max=255"`
}

// A ClientUser is the user data sent to a client
type ClientUser struct {
	Email     string    `json:"email"`
	Expires   time.Time `json:"expires"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
}

func login(w http.ResponseWriter, r *http.Request) {
	// Get request data
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	err := validate.Struct(user)
	if err != nil {
		http.Error(w, "Validation failed", http.StatusBadRequest)
		return
	}

	// Get user data from DB
	var result User
	users.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&result)

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	if err != nil {
		// Incorrect password
		http.Error(w, "Incorrect e-mail or password", http.StatusUnauthorized)
		return
	}
	expires := time.Now().AddDate(0, 0, 30)
	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": result.Email,
		"home":  result.Home,
		"exp":   expires,
		"iat":   time.Now(),
	})
	tokenString, _ := token.SignedString([]byte(*secret))
	// Set cookie
	tokenCookie := http.Cookie{Name: "access_token", Value: tokenString, Expires: expires, HttpOnly: true, Secure: true}
	if *dev {
		tokenCookie.Secure = false
	}
	http.SetCookie(w, &tokenCookie)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	json.NewEncoder(w).Encode(ClientUser{result.Email, expires, result.FirstName, result.LastName})
}

func renew(w http.ResponseWriter, r *http.Request) {
	// Get JWT
	cookie, err := r.Cookie("access_token")
	if err != nil {
		log.Println("Error: No token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(*secret), nil
	})

	if err != nil {
		// Invalid token
		log.Println("Error: Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		// Invalid token
		log.Println("Error: Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	// Get email from JWT
	email, _ := claims["email"].(string)

	// Get user data from DB
	var result User
	users.FindOne(context.TODO(), bson.M{"email": email}).Decode(&result)

	expires := time.Now().AddDate(0, 0, 30)

	// Create JWT token
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": result.Email,
		"home":  result.Home,
		"exp":   expires,
		"iat":   time.Now(),
	})
	tokenString, _ := token.SignedString([]byte(*secret))
	// Set cookie
	tokenCookie := http.Cookie{Name: "access_token", Value: tokenString, Expires: expires, HttpOnly: true, Secure: true}
	if *dev {
		tokenCookie.Secure = false
	}
	http.SetCookie(w, &tokenCookie)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	json.NewEncoder(w).Encode(ClientUser{result.Email, expires, result.FirstName, result.LastName})
}

func logout(w http.ResponseWriter, r *http.Request) {
	// Set cookie
	cookie := http.Cookie{Name: "access_token", Value: "", Expires: time.Time{}, HttpOnly: true, Secure: true}
	if *dev {
		cookie.Secure = false
	}
	http.SetCookie(w, &cookie)
}
