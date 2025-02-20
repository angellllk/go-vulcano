package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB defines the database instance containing the
// connection to the SQLite type database.
type DB struct {
	conn *gorm.DB
}

// New returns a new *DB instance.
func New() (*DB, error) {
	conn, err := gorm.Open(sqlite.Open("db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db := &DB{conn: conn}

	if err = db.Migrate(); err != nil {
		return nil, err
	}
	return db, err
}

// Migrate migrates the current database structures.
func (db *DB) Migrate() error {
	return db.conn.AutoMigrate(PSConfig{}, PluginsDB{})
}

// UpdateSettings update current settings.
func (db *DB) UpdateSettings(data Settings) error {
	var psConfig PSConfig
	if err := db.conn.FirstOrCreate(&psConfig, PSConfig{Model: gorm.Model{ID: 1}}).Error; err != nil {
		return err
	}

	data.PSConfig.Model.ID = psConfig.Model.ID

	if err := db.conn.Save(&data.PSConfig).Error; err != nil {
		return err
	}

	var pluginsDB PluginsDB
	if err := db.conn.FirstOrCreate(&pluginsDB, PluginsDB{Model: gorm.Model{ID: 1}}).Error; err != nil {
		return err
	}

	data.PluginsDB.Model.ID = pluginsDB.Model.ID

	if err := db.conn.Save(&data.PluginsDB).Error; err != nil {
		return err
	}

	return nil
}

// FetchSettings fetches the last used settings.
func (db *DB) FetchSettings() Settings {
	var result Settings
	db.conn.First(&result.PSConfig)
	db.conn.First(&result.PluginsDB)
	return result
}
