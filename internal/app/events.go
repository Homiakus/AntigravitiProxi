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
	done := make(chan struct{})
	var once sync.Once

	h.mu.Lock()
	h.clients[c] = struct{}{}
	hist := append([]Event(nil), h.history...)
	h.mu.Unlock()

	go func() {
		for _, e := range hist {
			select {
			case <-done:
				return
			case c <- e:
			}
		}
	}()

	cancel := func() {
		once.Do(func() {
			close(done)
			h.mu.Lock()
			delete(h.clients, c)
			h.mu.Unlock()
		})
	}
	return c, cancel
}
func eventJSON(e Event) string { b, _ := json.Marshal(e); return string(b) }
