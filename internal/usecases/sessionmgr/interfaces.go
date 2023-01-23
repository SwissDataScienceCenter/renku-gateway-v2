package sessionmgr

import "github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"

type SessionWriter interface {
	Write(models.Session) error
}

type SessionRemover interface {
	Remove(sessionID string) error
}

type SessionReader interface {
	Read(sessionID string) (models.Session, error)
}

type SessionReaderWriterRemover interface {
	SessionReader
	SessionWriter
	SessionRemover
}
