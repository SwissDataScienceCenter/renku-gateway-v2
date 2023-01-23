package tokenmgr

import "github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"

type RefreshTokenManager struct {
	refreshStore RefreshTokenReaderWriterRemover
	accessStore AccessTokenReaderWriterRemover
}

func RefreshAccessToken(accToken models.AccessToken, refToken models.RefreshToken) (newAccToken models.AccessToken, err error) {
	
}

