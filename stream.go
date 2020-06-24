package main

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// A DishStream is a Dish streamed from the DB
type DishStream struct {
	Full    *Dish  `bson:"fullDocument"`
	Type    string `bson:"operationType"`
	Changed struct {
		Updated *Dish `bson:"updatedFields"`
	} `bson:"updateDescription"`
}

// A DateStream is a Dish streamed from the DB
type DateStream struct {
	Date *Date  `bson:"fullDocument"`
	Type string `bson:"operationType"`
}

// StreamDishes streams changed Dishes from DB and sends to Hub
func StreamDishes() {
	dishesStream, _ := dishes.Watch(context.TODO(), mongo.Pipeline{}, options.ChangeStream().SetFullDocument(options.UpdateLookup))
	for dishesStream.Next(context.TODO()) {
		var data *DishStream
		dishesStream.Decode(&data)
		switch data.Type {
		case "insert":
			packet := &Packet{Method: "set", Params: Params{Changed: data.Full.Changed}, Data: Home{Dishes: []*Dish{data.Full}}}
			hub.Q <- &PendingPacket{Packet: packet, Home: data.Full.Home}
			break
		case "update":
			data.Changed.Updated.ID = data.Full.ID
			packet := &Packet{Method: "set", Params: Params{Changed: data.Full.Changed}, Data: Home{Dishes: []*Dish{data.Changed.Updated}}}
			hub.Q <- &PendingPacket{Packet: packet, Home: data.Full.Home}
			break
		}
	}
}

// StreamDates streams changed Dates from DB and sends to Hub
func StreamDates() {
	datesStream, _ := dates.Watch(context.TODO(), mongo.Pipeline{}, options.ChangeStream().SetFullDocument(options.UpdateLookup))
	for datesStream.Next(context.TODO()) {
		var data DateStream
		datesStream.Decode(&data)
		switch data.Type {
		case "insert", "update", "replace":
			packet := &Packet{Method: "set", Params: Params{Changed: data.Date.Changed}, Data: Home{Dates: []*Date{data.Date}}}
			hub.Q <- &PendingPacket{Packet: packet, Home: data.Date.Home}
			break
		default:
			break
		}
	}
}
