package server

import (
	"github.com/gofiber/fiber/v3"
	"go-vulcano/models"
	"go-vulcano/plugin"
)

// Handler defines an HTTP handler.
type Handler struct {
	pm *plugin.Manager // pm defines the *plugin.Manager used in operations.
}

// ScanHandler defines the handler for the /scan endpoint.
func (h *Handler) ScanHandler(ctx fiber.Ctx) error {
	br := response{
		Error:   true,
		Message: "Invalid data provided.",
	}

	var data ScanRequestAPI

	if err := ctx.Bind().Body(&data); err != nil {
		return ctx.Status(fiber.StatusUnprocessableEntity).JSON(br)
	}

	// Simple data validation
	if !data.Validate() {
		return ctx.Status(fiber.StatusUnprocessableEntity).JSON(br)
	}

	// Start the scan over targets
	results := h.pm.Scan(data.Targets, data.Mode)

	// Save results in database
	if err := h.pm.SaveScan(results); err != nil {
		br.Message = "Unexpected internal error occurred."
		return ctx.Status(fiber.StatusInternalServerError).JSON(br)
	}

	return ctx.Status(fiber.StatusOK).JSON(ScanResponse{
		Results: results,
	})
}

// SettingsHandler defines the handler for /settings endpoint.
func (h *Handler) SettingsHandler(ctx fiber.Ctx) error {
	br := response{
		Error:   true,
		Message: "Invalid data provided.",
	}

	var data models.SettingsAPI

	if err := ctx.Bind().Body(&data); err != nil {
		return ctx.Status(fiber.StatusUnprocessableEntity).JSON(br)
	}

	// Reconfigure settings based on user preferences
	if err := h.pm.Settings(data); err != nil {
		br.Message = "An error occurred during applying settings."
		return ctx.Status(fiber.StatusUnprocessableEntity).JSON(br)
	}

	return ctx.SendStatus(fiber.StatusOK)
}

// EnabledPluginsHandler defines the handler for /plugins endpoint.
func (h *Handler) EnabledPluginsHandler(ctx fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).JSON(EnabledPlugins{
		Plugins: h.pm.Count(),
	})
}
