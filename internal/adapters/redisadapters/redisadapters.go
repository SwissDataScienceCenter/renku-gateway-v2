// Package redisadapters contains functions for interacting with redis
package redisadapters

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/go-redis/redis/v9"
	"golang.org/x/net/context"
)

// RedisAdapter contains a redis client
type RedisAdapter struct {
	Rdb redis.Client
}

// Write functions

// WriteSession writes the associated ID, type, expiration and tokenID of a session to Redis
func (r *RedisAdapter) WriteSession(ctx context.Context, session models.Session) error {

	accessTokenList, err := json.Marshal(session.TokenIDs)
	if err != nil {
		return err
	}

	return r.Rdb.HSet(
		ctx,
		"session-"+session.ID,
		"type",
		session.Type,
		"expiresAt",
		session.ExpiresAt.Unix(),
		"tokenIds",
		accessTokenList,
	).Err()
}

// WriteAccessToken writes the associated ID, access token value, expiration, tokenID and refresh URL of an access token to Redis
func (r *RedisAdapter) WriteAccessToken(ctx context.Context, accessToken models.AccessToken) error {

	return r.Rdb.HSet(
		ctx,
		"accessTokens-"+accessToken.ID,
		"accessToken",
		accessToken.Value,
		"expiresAt",
		accessToken.ExpiresAt.Unix(),
		"URL",
		accessToken.URL,
		"type",
		accessToken.Type,
	).Err()
}

// WriteRefreshToken writes the associated ID, access token value, expiration and tokenID of a refresh token to Redis
func (r *RedisAdapter) WriteRefreshToken(ctx context.Context, refreshToken models.RefreshToken) error {

	return r.Rdb.HSet(
		ctx,
		"refreshTokens-"+refreshToken.ID,
		"refreshToken",
		refreshToken.Value,
		"expiresAt",
		refreshToken.ExpiresAt.Unix(),
	).Err()
}

// WriteToIndexExpiringTokens writes the associated expiration and tokenID of an access token to Redis
func (r *RedisAdapter) WriteToIndexExpiringTokens(ctx context.Context, accessToken models.AccessToken) error {

	var z1 redis.Z
	z1.Score = float64(accessToken.ExpiresAt.Unix())
	z1.Member = accessToken.ID

	return r.Rdb.ZAdd(
		ctx,
		"indexExpiringTokens",
		z1,
	).Err()
}

// WriteProjectToken writes the project ID and associated expiration and tokenID of a project to Redis
func (r *RedisAdapter) WriteProjectToken(ctx context.Context, projectID int, accessToken models.AccessToken) error {

	z1 := redis.Z{
		Score:  float64(accessToken.ExpiresAt.Unix()),
		Member: accessToken.ID,
	}

	return r.Rdb.ZAdd(
		ctx,
		"projectTokens-"+strconv.Itoa(projectID),
		z1,
	).Err()
}

// Remove/delete functions

// RemoveSession removes a session entry from Redis
func (r *RedisAdapter) RemoveSession(ctx context.Context, sessionID string) error {

	return r.Rdb.Del(
		ctx,
		"session-"+sessionID,
	).Err()
}

// RemoveAccessToken removes an access token entry from Redis
func (r *RedisAdapter) RemoveAccessToken(ctx context.Context, accessTokenID string) error {

	return r.Rdb.Del(
		ctx,
		"accessTokens-"+accessTokenID,
	).Err()
}

// RemoveRefreshToken removes an access token entry from Redis
func (r *RedisAdapter) RemoveRefreshToken(ctx context.Context, refreshTokenID string) error {

	return r.Rdb.Del(
		ctx,
		"refreshTokens-"+refreshTokenID,
	).Err()
}

// RemoveFromIndexExpiringTokens removes an access token entry in the indexExpiringTokens sorted set from Redis
func (r *RedisAdapter) RemoveFromIndexExpiringTokens(ctx context.Context, accessToken models.AccessToken) error {

	var z1 redis.Z
	z1.Score = float64(accessToken.ExpiresAt.Unix())
	z1.Member = accessToken.ID

	return r.Rdb.ZRem(
		ctx,
		"indexExpiringTokens",
		z1,
	).Err()
}

// RemoveProjectToken removes an access token entry in a projectTokens sorted set from Redis
func (r *RedisAdapter) RemoveProjectToken(ctx context.Context, projectID int, accessToken models.AccessToken) error {

	var z1 redis.Z
	z1.Score = float64(accessToken.ExpiresAt.Unix())
	z1.Member = accessToken.ID

	return r.Rdb.ZRem(
		ctx,
		"projectTokens-"+strconv.Itoa(projectID),
		z1,
	).Err()
}

// Get functions

// GetSession reads the associated ID, type, expiration and tokenID of a session from Redis
func (r *RedisAdapter) GetSession(ctx context.Context, sessionID string) (models.Session, error) {

	output, err := r.Rdb.HGetAll(
		ctx,
		"session-"+sessionID,
	).Result()

	expiresAtInt64, err := strconv.ParseInt(output["expiresAt"], 10, 64)

	var accessTokenList []string
	err = json.Unmarshal([]byte(output["tokenIds"]), &accessTokenList)

	return models.Session{
		ID:        sessionID,
		Type:      output["type"],
		ExpiresAt: time.Unix(expiresAtInt64, 0),
		TokenIDs:  accessTokenList,
	}, err
}

// GetAccessToken reads the associated ID, access token value, expiration, tokenID and refresh URL of an access token from Redis
func (r *RedisAdapter) GetAccessToken(ctx context.Context, tokenID string) (models.AccessToken, error) {

	output, err := r.Rdb.HGetAll(
		ctx,
		"accessTokens-"+tokenID,
	).Result()

	expiresAtInt64, err := strconv.ParseInt(output["expiresAt"], 10, 64)

	return models.AccessToken{
		ID:        tokenID,
		Value:     output["accessToken"],
		ExpiresAt: time.Unix(expiresAtInt64, 0),
		URL:       output["URL"],
		Type:      output["type"],
	}, err
}

// GetRefreshToken reads the associated ID, refresh token value, expiration and tokenID of a refresh token from Redis
func (r *RedisAdapter) GetRefreshToken(ctx context.Context, tokenID string) (models.RefreshToken, error) {

	output, err := r.Rdb.HGetAll(
		ctx,
		"refreshTokens-"+tokenID,
	).Result()

	expiresAtInt64, err := strconv.ParseInt(output["expiresAt"], 10, 64)

	return models.RefreshToken{
		ID:        tokenID,
		Value:     output["refreshToken"],
		ExpiresAt: time.Unix(expiresAtInt64, 0),
	}, err
}

// GetFromIndexExpiringTokens reads the associated expiration and tokenID of an access token from Redis
func (r *RedisAdapter) GetFromIndexExpiringTokens(ctx context.Context, startTime int64, stopTime int64) ([]string, error) {
	var expiringTokens []string

	zrangeargs := redis.ZRangeArgs{
		Key:     "indexExpiringTokens",
		Start:   startTime,
		Stop:    stopTime,
		ByScore: true,
	}

	zrange, err := r.Rdb.ZRangeArgsWithScores(
		ctx,
		zrangeargs,
	).Result()

	for _, expiringToken := range zrange {
		expiringTokens = append(expiringTokens, fmt.Sprintf("%v", expiringToken.Member))
	}

	return expiringTokens, err
}

// GetProjectTokens reads the project ID and associated expiration and tokenID of a project from Redis
func (r *RedisAdapter) GetProjectTokens(ctx context.Context, projectID int) ([]string, error) {
	var projectTokens []string

	zrangeargs := redis.ZRangeArgs{
		Key:     "projectTokens-" + strconv.Itoa(projectID),
		Start:   0,
		Stop:    999999,
		ByScore: false,
	}

	zrange, err := r.Rdb.ZRangeArgsWithScores(
		ctx,
		zrangeargs,
	).Result()

	for _, projectToken := range zrange {
		projectTokens = append(projectTokens, fmt.Sprintf("%v", projectToken.Member))
	}

	return projectTokens, err
}
