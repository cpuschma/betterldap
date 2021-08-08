package betterldap

import (
	"betterldap/internal/debug"
	"sync"
)

//1. Library functions get called
//2. Function constructs the operation & control packets
//3. Packets are encapsulated using an Envelope
//4. Library creates a message handler and registers the messageID
//   so incoming packages can be routed correctly
//5. Library runs ReadIncomingMessages in another thread
//6. When a new incoming messages arrives: extract the messageID
//7. Find the registered message handler for this ID
//8. If found: Pipe it to the handler

type Handler struct {
	messageID    int32
	receiverChan chan *Envelope
	closed       sync.Once
}

func NewHandler(messageID int32) *Handler {
	return &Handler{
		messageID:    messageID,
		receiverChan: make(chan *Envelope),
	}
}

func (m *Handler) Close() {
	m.closed.Do(func() {
		debug.Log("")
		close(m.receiverChan)
	})
}

func (m *Handler) Receive() (*Envelope, error) {
	debug.Log("Waiting for incoming messages from message bus")
	data, ok := <-m.receiverChan
	if !ok {
		return nil, nil
	}

	debug.Log("Forwarding incoming message")
	if err := data.err; err != nil {
		return nil, err
	}

	return data, nil
}
