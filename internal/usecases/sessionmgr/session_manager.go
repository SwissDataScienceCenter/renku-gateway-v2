package sessionmgr

import "github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"

type SessionManager struct {
	store SessionReaderWriterRemover
}

func (s *SessionManager) Refresh(session models.Session) (newSession models.Session, err error) {
	
}

func (s *SessionManager) Logout(sessionID string) (err error) {
	s.store.Remove(sessionID)
}