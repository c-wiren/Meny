package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	m "github.com/keighl/metabolize"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 100000
)

// A MetaData represents data from the Metabolize package
type MetaData struct {
	Image string `meta:"og:image"`
	Title string `meta:"og:title,title"`
	Site  string `meta:"og:site_name"`
}

// A Packet is the data sent between server and client
type Packet struct {
	Method string `json:"method"`
	Params Params `json:"params,omitempty"`
	Data   Home   `json:"data,omitempty"`
}

// A Params is parameters for a Packet
type Params struct {
	Changed time.Time          `json:"changed,omitempty"`
	ID      primitive.ObjectID `json:"id,omitempty"`
}

// An Error is a error to send to the client
type Error struct {
	Message string `json:"error"`
}

// A Home is the data in a Packet
type Home struct {
	Dishes []*Dish `json:"dishes,omitempty" validate:"dive"`
	Dates  []*Date `json:"dates,omitempty" validate:"dive"`
}

// A Dish is part of a Home
type Dish struct {
	ID          primitive.ObjectID `json:"id,omitempty" bson:"localId,omitempty"`
	Name        *string            `json:"name,omitempty" bson:"name,omitempty" validate:"max=255"`
	Description *string            `json:"description,omitempty" bson:"description,omitempty" validate:"max=2047"`
	Link        *string            `json:"link,omitempty" bson:"link,omitempty" validate:"max=2047,url"`
	Image       *string            `json:"image,omitempty" bson:"image,omitempty" validate:"max=2047,url"`
	Changed     time.Time          `json:"-" bson:"changed,omitempty"`
	MetaTitle   *string            `json:"metaTitle,omitempty" bson:"metaTitle,omitempty"`
	MetaSite    *string            `json:"metaSite,omitempty" bson:"metaSite,omitempty"`
	Deleted     bool               `json:"deleted,omitempty" bson:"deleted,omitempty"`
	Home        primitive.ObjectID `json:"-" bson:"home,omitempty"`
}

// A Date is part of a Home
type Date struct {
	Date    string               `json:"date,omitempty" bson:"date,omitempty" validate:"required,len=10"`
	Dishes  []primitive.ObjectID `json:"dishIds,omitempty" bson:"dishIds,omitempty" validate:"max=100"`
	Changed time.Time            `json:"-" bson:"changed,omitempty"`
	Home    primitive.ObjectID   `json:"-" bson:"home,omitempty"`
}

// A Client represents each connected user
type Client struct {
	C    *websocket.Conn
	Q    chan *Packet
	Home primitive.ObjectID
}

// Writer writes data to a client
func (c *Client) Writer() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.C.Close()
	}()
	for {
		select {
		case packet, ok := <-c.Q:
			c.C.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.C.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			err := c.C.WriteJSON(packet)
			if err != nil {
				return
			}
		case <-ticker.C:
			c.C.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.C.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}

// Reader reads data from a client
func (c *Client) Reader() {
	defer func() {
		hub.Remove <- c
		close(c.Q)
		c.C.Close()
	}()
	c.C.SetReadLimit(maxMessageSize)
	c.C.SetReadDeadline(time.Now().Add(pongWait))
	c.C.SetPongHandler(func(string) error { c.C.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		// Read request
		var request Packet
		err := c.C.ReadJSON(&request)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				log.Println("Error:", err)
			}
			break
		}
		// Choose action
		switch request.Method {

		// Method GET
		case "get":
			// Get dishes newer than "Changed" parameter
			var response Packet
			cur, _ := dishes.Find(context.TODO(), bson.M{"changed": bson.M{"$gt": request.Params.Changed}, "home": c.Home})
			for cur.Next(context.TODO()) {
				var dish Dish
				cur.Decode(&dish)
				// Get latest changed date
				if dish.Changed.After(response.Params.Changed) {
					response.Params.Changed = dish.Changed
				}
				response.Data.Dishes = append(response.Data.Dishes, &dish)
			}
			// Get dates newer than "Changed" parameter
			cur, _ = dates.Find(context.TODO(), bson.M{"changed": bson.M{"$gt": request.Params.Changed}, "home": c.Home})
			for cur.Next(context.TODO()) {
				var date Date
				cur.Decode(&date)
				// Get latest changed date
				if date.Changed.After(response.Params.Changed) {
					response.Params.Changed = date.Changed
				}
				response.Data.Dates = append(response.Data.Dates, &date)
			}
			// Set reciever action
			response.Method = "set"
			response.Params.ID = request.Params.ID
			// Write
			c.Q <- &response
			break

		// Method SET
		case "set":
			/* 			err := validate.Struct(request.Data)
			   			if err != nil {
			   				log.Println(err)
			   				break
			   			} */
			// Prepare data
			var deleted []primitive.ObjectID
			for _, dish := range request.Data.Dishes {
				dish.Changed = time.Now()
				dish.Home = c.Home
				if dish.Deleted {
					deleted = append(deleted, dish.ID)
				}
				if dish.Link != nil {
					if *dish.Link != "" {
						metaData := new(MetaData)
						res, _ := http.Get(*dish.Link)
						m.Metabolize(res.Body, metaData)
						dish.Image = &metaData.Image
						dish.MetaTitle = &metaData.Title
						dish.MetaSite = &metaData.Site
					} else {
						empty := ""
						dish.Image = &empty
						dish.MetaTitle = &empty
						dish.MetaSite = &empty
					}
				}
			}
			for _, date := range request.Data.Dates {
				date.Changed = time.Now()
				date.Home = c.Home
			}
			// Write data
			if len(deleted) > 0 {
				err, res := dates.UpdateMany(context.TODO(), bson.M{"dishIds": bson.M{"$in": deleted}}, bson.M{"$pull": bson.M{"dishIds": bson.M{"$in": deleted}}})
				log.Println(err, res)
			}
			if len(request.Data.Dishes) > 0 {
				var dishesUpdate []mongo.WriteModel
				for _, dish := range request.Data.Dishes {
					operation := mongo.NewUpdateOneModel()
					operation.SetFilter(bson.M{"localId": dish.ID, "home": c.Home})
					operation.SetUpdate(bson.M{"$set": dish})
					operation.SetUpsert(true)
					dishesUpdate = append(dishesUpdate, operation)
				}
				dishes.BulkWrite(context.TODO(), dishesUpdate)
			}
			if len(request.Data.Dates) > 0 {
				var datesUpdate []mongo.WriteModel
				for _, date := range request.Data.Dates {
					operation := mongo.NewUpdateOneModel()
					operation.SetFilter(bson.M{"date": date.Date, "home": c.Home})
					operation.SetUpdate(date)
					operation.SetUpsert(true)
					datesUpdate = append(datesUpdate, operation)
				}
				dates.BulkWrite(context.TODO(), datesUpdate)
			}
			c.Q <- &Packet{Method: "confirm", Params: Params{ID: request.Params.ID}}
			break
		}

	}
}

func ws(w http.ResponseWriter, r *http.Request) {
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

	// Get home ID from JWT
	str, _ := claims["home"].(string)
	home, err := primitive.ObjectIDFromHex(str)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	// Initialize Websocket connection
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := Client{c, make(chan *Packet, 10), home}
	// Add user channel to home group
	hub.Add <- &client
	// Start writer goroutine
	go client.Writer()
	go client.Reader()
}
