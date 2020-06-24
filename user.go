package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PATCH":
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

		// Get request data
		var user PatchUser
		json.NewDecoder(r.Body).Decode(&user)
		// Validate input
		err = validate.Struct(user)
		if err != nil {
			http.Error(w, "Validation failed", http.StatusBadRequest)
			return
		}

		// Check password if required
		if user.NewPassword != "" || user.Email != "" {
			// Get user data from DB
			var result User
			users.FindOne(context.TODO(), bson.M{"email": email}).Decode(&result)

			// Compare passwords
			err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
			if err != nil {
				// Incorrect password
				log.Println("Error: Incorrect password")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		// Hash new password
		if user.NewPassword != "" {
			// Hashing password
			newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(user.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				// Hashing failed
				log.Println("Error: Error hashing password")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			user.NewPassword = string(newPasswordHash)
		}
		_, err = users.UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$set": user})
		if err != nil {
			log.Println("Error: Error updating user")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		break
	case "POST":
		// Get request data
		var user NewUser
		json.NewDecoder(r.Body).Decode(&user)

		// Validate input
		err := validate.Struct(user)
		if err != nil {
			http.Error(w, "Validation failed", http.StatusBadRequest)
			return
		}

		// Parse Email validation token
		emailToken, err := jwt.Parse(user.Token, func(token *jwt.Token) (interface{}, error) {
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
		claims, ok := emailToken.Claims.(jwt.MapClaims)

		if !ok || !emailToken.Valid {
			// Invalid token
			log.Println("Error: Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		// Get data from JWT
		user.Email, _ = claims["email"].(string)
		code, _ := claims["code"].(string)

		// Create hash from code
		h := hmac.New(sha256.New, []byte(*secret))
		h.Write([]byte{byte(user.Code)})
		codeHash := hex.EncodeToString(h.Sum(nil))

		if code != codeHash {
			log.Println("Error: Invalid code")
			http.Error(w, "Invalid code", http.StatusUnauthorized)
			return
		}

		count, err := users.CountDocuments(context.TODO(), bson.M{"email": user.Email})
		if err != nil {
			log.Println(err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		if count != 0 {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		// Hashing password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			// Hashing failed
			log.Println("Error: Error hashing password")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		user.Password = string(passwordHash)
		result, err := homes.InsertOne(context.TODO(), bson.M{})

		// Create initial home
		if err != nil {
			log.Println("Error: Failed creating home:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		// Add home to user
		user.Home = result.InsertedID.(primitive.ObjectID)

		// Create user
		_, err = users.InsertOne(context.TODO(), user)
		if err != nil {
			log.Println("Error: Failed creating user:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		// Create JWT token
		expires := time.Now().AddDate(0, 0, 30)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": user.Email,
			"home":  user.Home,
			"exp":   expires,
			"iat":   time.Now(),
		})
		tokenString, _ := token.SignedString([]byte(*secret))

		// Set cookie
		tokenCookie := http.Cookie{Name: "access_token", Value: tokenString, Expires: expires, HttpOnly: true, Secure: true}
		http.SetCookie(w, &tokenCookie)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(ClientUser{user.Email, expires, user.FirstName, user.LastName})
		break
	}
}
