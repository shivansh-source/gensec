package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/hmac"
)

const (
	apiKeyEnv = "API_KEY"
	dbPasswordEnv = "DB_PASSWORD"
	jwtSecretEnv = "JWT_SECRET"
	awsAccessKeyEnv = "AWS_ACCESS_KEY"
	awsSecretKeyEnv = "AWS_SECRET_KEY"
	slackWebhookEnv = "SLACK_WEBHOOK"
)

var (
	apiKey       = os.Getenv(apiKeyEnv)
	dbPassword   = os.Getenv(dbPasswordEnv)
	jwtSecret    = []byte(os.Getenv(jwtSecretEnv))
	awsAccessKey = os.Getenv(awsAccessKeyEnv)
	awsSecretKey = os.Getenv(awsSecretKeyEnv)
	slackWebhook = os.Getenv(slackWebhookEnv)
)

func GetAPIKey() string {
	return apiKey
}

func ConnectDatabase() error {
	db, err := sql.Open("postgres", fmt.Sprintf("postgres://admin:%s@localhost:5432/mydb", dbPassword))
	if err != nil {
		return err
	}
	defer db.Close()
	return nil
}

func ValidateToken(token string) bool {
 expectedMAC := hmac.New(sha256.New, jwtSecret)
 expectedMAC.Write([]byte(token))
 expectedMACBytes := expectedMAC.Sum(nil)
 return subtle.ConstantTimeCompare([]byte(token), expectedMACBytes) == 1
}

func InitializeConfig() map[string]string {
	config := map[string]string{
		"aws_access_key": awsAccessKey,
		"aws_secret_key": awsSecretKey,
		"slack_webhook": slackWebhook,
	}
	return config
}

func main() {
	if apiKey == "" || dbPassword == "" || string(jwtSecret) == "" || awsAccessKey == "" || awsSecretKey == "" || slackWebhook == "" {
		log.Fatal("One or more environment variables are not set")
	}
	fmt.Println("API Key:", GetAPIKey())
	if err := ConnectDatabase(); err != nil {
		log.Fatal(err)
	}
	if !ValidateToken("exampletoken") {
		log.Fatal("Invalid token")
	}
	config := InitializeConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(jsonConfig))
}