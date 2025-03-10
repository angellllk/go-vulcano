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
	return db.conn.AutoMigrate(PSConfigDB{}, PluginsDB{}, ScanResultDB{}, SubdomainDB{})
}

// SaveScan saves the scan data.
func (db *DB) SaveScan(data *ScanResultDB) error {
	if err := db.conn.Create(data).Error; err != nil {
		return err
	}
	return nil
}

// UpdateSettings update current settings.
func (db *DB) UpdateSettings(data SettingsDB) error {
	var psConfig PSConfigDB
	if err := db.conn.FirstOrCreate(&psConfig, PSConfigDB{Model: gorm.Model{ID: 1}}).Error; err != nil {
		return err
	}
	data.PSConfigDB.Model.ID = psConfig.Model.ID
	if err := db.conn.Save(&data.PSConfigDB).Error; err != nil {
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
func (db *DB) FetchSettings() SettingsDB {
	var result SettingsDB
	db.conn.First(&result.PSConfigDB)
	db.conn.First(&result.PluginsDB)
	return result
}
