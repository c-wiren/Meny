package main

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// A PendingPacket is a packet waiting to be sent
type PendingPacket struct {
	Home   primitive.ObjectID
	Packet *Packet
}

// A Hub distributes packets to Clients
type Hub struct {
	Q      chan *PendingPacket
	Add    chan *Client
	Remove chan *Client
	Homes  map[string][]chan *Packet
}

// Init initializes a Hub
func (h *Hub) Init() {
	h.Q = make(chan *PendingPacket, 10)
	h.Add = make(chan *Client)
	h.Remove = make(chan *Client)
	h.Homes = make(map[string][]chan *Packet)
}

// Run starts a Hub
func (h *Hub) Run() {
	for {
		select {
		case packet := <-h.Q:
			for _, client := range h.Homes[packet.Home.String()] {
				client <- packet.Packet
			}
		case c := <-h.Add:
			h.Homes[c.Home.String()] = append(h.Homes[c.Home.String()], c.Q)
		case c := <-h.Remove:
			index := -1
			homeUsers := h.Homes[c.Home.String()]
			for i, homeUser := range homeUsers {
				if homeUser == c.Q {
					index = i
					break
				}
			}
			if index != -1 {
				homeUsers[index] = homeUsers[len(homeUsers)-1]
				h.Homes[c.Home.String()] = homeUsers[:len(homeUsers)-1]
			}
		}
	}
}
