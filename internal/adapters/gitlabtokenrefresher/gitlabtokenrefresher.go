package gitlabtokenrefresher

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/redisadapters"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/go-co-op/gocron"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	Type         string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	CreatedAt    int64  `json:"created_at"`
}

func ScheduleRefreshExpiringTokens(ctx context.Context, redisAdapter redisadapters.RedisAdapter, gitlabTokenRefreshURL string, clientID string, clientSecret string, minsToExpiration int) error {
	// schedule token refresh evaluations
	s := gocron.NewScheduler(time.UTC)
	job, err := s.Every(minsToExpiration).Minutes().Do(refreshExpiringTokens, ctx, redisAdapter, gitlabTokenRefreshURL, clientID, clientSecret, minsToExpiration)
	s.StartBlocking()
	if err != nil {
		log.Printf("Reading body failed: %s", err)
	} else {
		log.Printf("Job starting: %v", job)
	}
	return err
}

func refreshExpiringTokens(ctx context.Context, redisAdapter redisadapters.RedisAdapter, gitlabTokenRefreshURL string, clientID string, clientSecret string, minsToExpiration int) error {
	expiringTokenIDs, err := redisAdapter.GetExpiringAccessTokenIDs(ctx, time.Now(), time.Now().Add(time.Minute*time.Duration(minsToExpiration)))
	if err != nil {
		log.Printf("Reading body failed: %s", err)
		return err
	}

	for _, expiringTokenID := range expiringTokenIDs {
		myRefreshToken, err := redisAdapter.GetRefreshToken(ctx, expiringTokenID)
		if err != nil {
			log.Printf("Reading body failed: %s", err)
			return err
		}

		myAccessToken, err := redisAdapter.GetAccessToken(ctx, expiringTokenID)
		if err != nil {
			log.Printf("Reading body failed: %s", err)
			return err
		}

		params := url.Values{}
		params.Add("client_id", clientID)
		params.Add("client_secret", clientSecret)
		params.Add("refresh_token", myRefreshToken.Value)
		params.Add("grant_type", "refresh_token")
		params.Add("redirect_uri", myAccessToken.URL)

		resp, err := http.PostForm(gitlabTokenRefreshURL, params)
		if err != nil {
			log.Printf("Request Failed: %s", err)
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		// Log the request body
		bodyString := string(body)
		log.Print(bodyString)

		// Unmarshal result
		token := tokenResponse{}
		err = json.Unmarshal(body, &token)
		if err != nil {
			log.Printf("Reading body failed: %s", err)
			return err
		} else {
			log.Printf("New token received")
		}

		err = redisAdapter.SetAccessToken(ctx, models.AccessToken{
			ID:        myAccessToken.ID,
			Value:     token.AccessToken,
			ExpiresAt: time.Unix(token.CreatedAt+token.ExpiresIn, 0),
			URL:       myAccessToken.URL,
			Type:      "git",
		})

		err = redisAdapter.SetRefreshToken(ctx, models.RefreshToken{
			ID:        myRefreshToken.ID,
			Value:     token.RefreshToken,
			ExpiresAt: time.Unix(token.CreatedAt+token.ExpiresIn, 0),
		})
	}

	log.Printf("%v expiring access tokens refreshed, evaluating again in %v minutes", len(expiringTokenIDs), minsToExpiration)
	return err
}
