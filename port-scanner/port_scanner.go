package port_scanner

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"go-vulcano/models"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PortScanner scans a range of ports in one phase using a moderate timeout per port.
// It uses a dynamic worker pool with rate limiting to avoid flooding the target.
type PortScanner struct {
	StartPort int           // Starting port number.
	EndPort   int           // Ending port number.
	Timeout   time.Duration // Timeout per port.

	// Dynamic scaling parameters.
	MinWorkers  int           // Minimum number of workers to start.
	MaxWorkers  int           // Maximum allowed workers.
	IdleTimeout time.Duration // Idle time before a worker exits.

	// Rate limiting: minimum delay between connection attempts.
	RateLimit time.Duration
}

// Name returns the scanner name.
func (ps *PortScanner) Name() string {
	return "Port Scanner"
}

// Configure configures the scanner.
func (ps *PortScanner) Configure(cfg Config) {
	ps.StartPort = cfg.StartPort
	ps.EndPort = cfg.EndPort
	ps.Timeout = time.Millisecond * time.Duration(cfg.Timeout)
	ps.MinWorkers = cfg.MinWorkers
	ps.MaxWorkers = cfg.MaxWorkers
	ps.IdleTimeout = time.Millisecond * time.Duration(cfg.IdleTimeout)
	ps.RateLimit = time.Millisecond * 10
}

// worker defines the logic of finding open ports using TCP.
func (ps *PortScanner) worker(target *models.TargetInfo, currentWorkers int32, portChan chan int, resultsChan chan int, ctx context.Context, limiter *time.Ticker, wg *sync.WaitGroup) {
	defer wg.Done()
	// Each worker gets its own idle timer.
	idleTimer := time.NewTimer(ps.IdleTimeout)
	defer idleTimer.Stop()
	var dialer net.Dialer
	for {
		select {
		case <-ctx.Done():
			atomic.AddInt32(&currentWorkers, -1)
			return
		case port, ok := <-portChan:
			if !ok {
				atomic.AddInt32(&currentWorkers, -1)
				return
			}
			// Wait for a rate limiter token.
			<-limiter.C

			// Reset idle timer.
			if !idleTimer.Stop() {
				<-idleTimer.C
			}
			idleTimer.Reset(ps.IdleTimeout)

			address := fmt.Sprintf("%s:%d", target.Domain, port)
			// Create a per-dial context with the specified timeout.
			dialCtx, cancelDial := context.WithTimeout(ctx, ps.Timeout)
			startTime := time.Now()
			conn, err := dialer.DialContext(dialCtx, "tcp", address)
			duration := time.Since(startTime)
			cancelDial()

			// Apply a simple throttle if the dial took too long.
			if duration > ps.Timeout {
				time.Sleep(100 * time.Millisecond)
			}

			if err == nil {
				resultsChan <- port
				conn.Close()
				logrus.Debugf("Port %d open (in %v)", port, duration)
			} else {
				logrus.Tracef("Port %d closed (error: %v, in %v)", port, err, duration)
			}
		case <-idleTimer.C:
			// Worker idle: exit.
			atomic.AddInt32(&currentWorkers, -1)
			return
		}
	}
}

// Run performs the port scan for the given target.
func (ps *PortScanner) Run(target *models.TargetInfo) (*models.DTO, error) {
	logrus.Infof("Starting Single Phase Port Scan on %s", target.Domain)

	// Set an overall context timeout based on the number of ports plus an extra buffer.
	totalTimeout := time.Duration(ps.EndPort-ps.StartPort)*ps.Timeout + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	// Attach the target domain to the context.
	ctx = context.WithValue(ctx, "domain", target.Domain)

	// Create channels for ports and results.
	portChan := make(chan int, 100)
	resultsChan := make(chan int, ps.EndPort-ps.StartPort+1)
	limiter := time.NewTicker(ps.RateLimit)
	defer limiter.Stop()

	var wg sync.WaitGroup
	// Use an atomic counter for the current number of workers.
	var currentWorkers = int32(ps.MinWorkers)

	// Spawn the initial worker pool.
	for i := 0; i < ps.MinWorkers; i++ {
		wg.Add(1)
		go ps.worker(target, currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
	}

	// Producer: enqueue all port numbers.
	go func() {
		for port := ps.StartPort; port <= ps.EndPort; port++ {
			select {
			case <-ctx.Done():
				return
			default:
				portChan <- port
				// Dynamically spawn more workers if pending tasks exceed threshold.
				if len(portChan) > 10 && atomic.LoadInt32(&currentWorkers) < int32(ps.MaxWorkers) {
					atomic.AddInt32(&currentWorkers, 1)
					wg.Add(1)
					go ps.worker(target, currentWorkers, portChan, resultsChan, ctx, limiter, &wg)
				}
			}
		}
		close(portChan)
	}()

	wg.Wait()
	close(resultsChan)

	// Collect and sort the open ports.
	var openPorts []int
	for port := range resultsChan {
		openPorts = append(openPorts, port)
	}
	sort.Ints(openPorts)
	logrus.Infof("Open ports on %s: %v", target.Domain, openPorts)

	// Cache the results
	var result models.DTO
	result.Ports = openPorts

	return &result, nil
}
