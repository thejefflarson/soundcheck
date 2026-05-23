// Test case: concurrency-correctness (CWE-833, CWE-820, CWE-667)
//
// Each function below contains a structural concurrency bug that runs
// fine in single-threaded tests but produces deadlock, lost wakeup, or
// data race under contention. Invoking concurrency-correctness should
// flag each one.

package badconcurrency

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	mu       sync.Mutex
	endpoint string
	last     *Response
}

type Response struct {
	Body []byte
}

// BUG 1 (CWE-833 lock-across-blocking-IO): mu held for the network RTT;
// every other caller of Fetch waits for that one HTTP request.
func (c *Client) Fetch(ctx context.Context, h *http.Client) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, "GET", c.endpoint, nil)
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.last = &Response{}
	return c.last, nil
}

// BUG 2 (CWE-833 lock-order): Transfer can deadlock with another goroutine
// running Transfer(B, A, ...) — A,B vs B,A acquire order.
type Account struct {
	mu      sync.Mutex
	balance int
}

func Transfer(a, b *Account, amount int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	a.balance -= amount
	b.balance += amount
}

// BUG 3 (CWE-820 wrong memory order): ready is set/checked without
// synchronization; consumer can observe ready=true before payload is
// visible. Go's race detector flags this; pattern is also wrong in
// C++ with memory_order_relaxed.
type LazyValue struct {
	ready   atomic.Bool
	payload []byte
}

func (l *LazyValue) Init(data []byte) {
	l.payload = data
	l.ready.Store(true) // Go atomic.Bool is sequentially consistent, but
	                    // the payload write is NOT atomic — race.
}

func (l *LazyValue) Get() []byte {
	if l.ready.Load() {
		return l.payload
	}
	return nil
}

// BUG 4 (CWE-833): lock then sleep — anyone else waiting on mu stalls.
func (c *Client) Backoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	time.Sleep(5 * time.Second)
}

// BUG 5 (CWE-667 unbuffered channel under lock): the receiver of done
// needs c.mu to call Stop; sending blocks forever.
type Worker struct {
	mu   sync.Mutex
	done chan struct{}
}

func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.done <- struct{}{} // unbuffered; receiver may need w.mu → deadlock
}
