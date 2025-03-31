package port_scanner

import (
	"context"
	"fmt"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"go-vulcano/models"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPortScanner_Configure(t *testing.T) {
	var ps PortScanner

	cfg := models.PortScannerConfig{
		StartPort:   80,
		EndPort:     100,
		Timeout:     1000,
		MinWorkers:  5,
		MaxWorkers:  10,
		IdleTimeout: 5000,
	}

	ps.Configure(cfg)

	assert.Equal(t, 80, ps.StartPort)
	assert.Equal(t, 100, ps.EndPort)
	assert.Equal(t, time.Millisecond*1000, ps.Timeout)
	assert.Equal(t, 5, ps.MinWorkers)
	assert.Equal(t, 10, ps.MaxWorkers)
	assert.Equal(t, time.Millisecond*5000, ps.IdleTimeout)
}

func TestPortScanner_setInterface(t *testing.T) {
	var ps PortScanner
	err := ps.setInterface()
	assert.NoError(t, err)
	assert.NotEmpty(t, ps.Interface.Name)
}

func TestPortScanner_setGatewayMAC(t *testing.T) {
	var ps PortScanner
	err := ps.setInterface()
	assert.NoError(t, err)

	err = ps.setGatewayMAC()
	assert.NoError(t, err)
	assert.NotEmpty(t, ps.Interface.MAC)
}

func TestPortScanner_Run(t *testing.T) {
	app := fiber.New()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)

	go func() {
		if err := app.Listen(":8080"); err != nil {
			fmt.Println("Listen error:", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		if err := app.Shutdown(); err != nil {
			t.Errorf("Shutdown error: %v", err)
		}
	}()

	port := 8080
	ps := &PortScanner{
		StartPort:   port,
		EndPort:     port + 1,
		Timeout:     time.Millisecond * 10,
		MinWorkers:  1,
		MaxWorkers:  1,
		IdleTimeout: time.Millisecond * 10,
		RateLimit:   time.Millisecond * 10,
	}

	target := &models.TargetInfo{
		IP:     net.ParseIP("127.0.0.1"),
		Domain: "localhost",
	}

	opts := models.Options{
		ScanMode: "tcp",
	}

	results, err := ps.Run(target, &opts)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Contains(t, results.Ports, port)

	cancel()
	wg.Wait()
}
