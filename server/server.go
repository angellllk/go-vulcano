package server

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/sirupsen/logrus"
	"go-vulcano/database"
	"go-vulcano/plugin"
)

func Start() {
	// Set log level
	logrus.SetLevel(logrus.DebugLevel)

	// Initiate database
	db, err := database.New()
	if err != nil {
		logrus.Fatalf("couldn't create database: %v", err)
	}

	// Initiate HTTP Handler
	h := Handler{pm: plugin.NewManager(db)}

	// Prepare fiber app
	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Origin", "Accept"},
		AllowOrigins: []string{"http://localhost:5173"},
	}))

	// Define routes
	app.Post("/scan", h.ScanHandler)
	app.Post("/settings", h.SettingsHandler)
	app.Get("/plugins", h.EnabledPluginsHandler)

	// Start listening to port
	app.Listen(":8080")
}
