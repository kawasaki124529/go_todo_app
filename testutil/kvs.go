package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/go-redis/redis/v8"
)

func OpenRedisForTest(t *testing.T) *redis.Client {
	t.Helper()

	host := "127.0.0.1"
	port := "36379"
	if _, defined := os.LookupEnv("CI"); defined {
		port = "6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: "",
		DB:       0,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("failed to ping redis: %v", err)
	}
	return client
}
