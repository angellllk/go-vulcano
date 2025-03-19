package plugin

import "go-vulcano/models"

type Plugin interface {
	Name() string
	Run(target *models.TargetInfo, opts *models.Options) (*models.DTO, error)
}
