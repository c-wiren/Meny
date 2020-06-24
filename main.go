package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/go-playground/validator"
	"github.com/gorilla/websocket"
	"github.com/mailgun/mailgun-go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var addr = flag.String("addr", ":5000", "http service address")
var pass = flag.String("pass", "", "db password")
var mgPass = flag.String("mg", "", "mailgun api-key")
var secret = flag.String("secret", "12345678", "JWT secret")
var cors = flag.String("cors", "http://localhost:8080", "allowed IP")
var dev = flag.Bool("dev", false, "development mode")
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
	return true
}} // use default options

var dishes, dates, users, homes *mongo.Collection

var hub = Hub{}

var mg *mailgun.MailgunImpl

var validate *validator.Validate

func main() {
	flag.Parse()
	mg = mailgun.NewMailgun("mg.meny.wiren.cc", *mgPass)
	mg.SetAPIBase(mailgun.APIBaseEU)

	validate = validator.New()

	// Connect to MongoDB
	log.Println("Connecting to DB...")
	var clientOptions = options.Client().ApplyURI("mongodb+srv://user:@cluster0-qer2c.mongodb.net/test?retryWrites=true&w=majority")
	clientOptions.SetAuth(options.Credential{Username: "user", Password: *pass})
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to DB")
	dishes = client.Database("db").Collection("dishes")
	dates = client.Database("db").Collection("dates")
	users = client.Database("db").Collection("users")
	homes = client.Database("db").Collection("homes")
	hub.Init()
	go hub.Run()
	go StreamDishes()
	go StreamDates()

	http.HandleFunc("/ws", ws)
	http.HandleFunc("/login", corsMiddleware(login))
	http.HandleFunc("/logout", corsMiddleware(logout))
	http.HandleFunc("/users", corsMiddleware(usersHandler))
	http.HandleFunc("/validate", corsMiddleware(validateEmail))
	log.Println("Server running on", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
