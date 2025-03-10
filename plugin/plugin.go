package plugin

import "go-vulcano/models"

type Plugin interface {
	Name() string
	Run(target *models.TargetInfo) (*models.DTO, error)
}
