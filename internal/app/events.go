package app

import (
	"encoding/json"
	"sync"
	"time"
)

type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}
type eventHub struct {
	mu      sync.Mutex
	history []Event
	clients map[chan Event]struct{}
}

func newEventHub() *eventHub { return &eventHub{clients: map[chan Event]struct{}{}} }
func (h *eventHub) publish(level, msg string) {
	e := Event{Time: time.Now(), Level: level, Message: msg}
	h.mu.Lock()
	h.history = append(h.history, e)
	if len(h.history) > 300 {
		h.history = h.history[len(h.history)-300:]
	}
	for c := range h.clients {
		select {
		case c <- e:
		default:
		}
	}
	h.mu.Unlock()
}
func (h *eventHub) subscribe() (chan Event, func()) {
	c := make(chan Event, 32)
	h.mu.Lock()
	h.clients[c] = struct{}{}
	hist := append([]Event(nil), h.history...)
	h.mu.Unlock()
	go func() {
		for _, e := range hist {
			c <- e
		}
	}()
	return c, func() { h.mu.Lock(); delete(h.clients, c); close(c); h.mu.Unlock() }
}
func eventJSON(e Event) string { b, _ := json.Marshal(e); return string(b) }
