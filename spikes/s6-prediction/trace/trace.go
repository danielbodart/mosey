// Package trace is the on-disk format for recorded keystroke/screen traces.
//
// A trace is one gzip'd JSON document. Screens are de-duplicated: events
// refer to them by index. Times are microseconds since the recorder started.
package trace

import (
	"compress/gzip"
	"encoding/json"
	"os"

	"mosey.spike/s6-prediction/screen"
)

type Kind string

const (
	Key Kind = "key" // bytes written to the pty by the scripted user
	Out Kind = "out" // bytes read from the pty, and the screen after them
)

type Event struct {
	T      int64  `json:"t"` // microseconds
	Kind   Kind   `json:"k"`
	Data   []byte `json:"d,omitempty"`
	Screen int    `json:"s"` // index into Screens (state after this event)
	Label  string `json:"l,omitempty"`
}

type Trace struct {
	Name    string           `json:"name"`
	Program string           `json:"program"`
	Cols    int              `json:"cols"`
	Rows    int              `json:"rows"`
	Seed    int64            `json:"seed"`
	Notes   string           `json:"notes,omitempty"`
	Screens []*screen.Screen `json:"screens"`
	Events  []Event          `json:"events"`
}

func (t *Trace) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	if err := json.NewEncoder(zw).Encode(t); err != nil {
		return err
	}
	return zw.Close()
}

func Load(path string) (*Trace, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var t Trace
	if err := json.NewDecoder(zr).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Keys returns the indices of key events in order.
func (t *Trace) Keys() []int {
	var ks []int
	for i, e := range t.Events {
		if e.Kind == Key {
			ks = append(ks, i)
		}
	}
	return ks
}
