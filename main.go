package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

var refresh_tokens map[string]RefreshToken

func main() {
	refresh_tokens = make(map[string]RefreshToken)
	fmt.Println("start")
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/test", TestToken)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type TokenPayload struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Username   string `json:"username"`
	Expiration int64  `json:"exp"`
}

type RefreshToken struct {
	Token      string
	Expiration time.Time
	Username   string
}
type RefreshRequest struct {
	Token string `json:"token"`
}

const token_duration_min = 10

func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !auth(creds.Username, creds.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt, refresh := new_jwt(creds.Username)

	fmt.Fprintf(w, "{\"token\": \"%s\", \"refresh\": \"%s\"}", jwt, refresh)
}

func auth(user string, password string) bool {
	if user == "admin" && password == "admin" {
		return true
	} else {
		return false
	}
}

func get_secret() string {
	return "WowThisIsSuperDupersecret"
}

func random_string(len int) string {
	bytes := make([]byte, len)
	_, _ = rand.Read(bytes)
	str := base64.RawStdEncoding.EncodeToString(bytes)
	return str
}

func new_jwt(username string) (string, string) {
	expiration := time.Now().Add(token_duration_min * time.Minute)
	header := "{\"alg\": \"HS256\", \"typ\": \"JWT\"}"
	issuer := "jojor.net"
	exp := expiration.Unix()
	sub := "userid76876875587"
	pld := TokenPayload{
		Issuer:     issuer,
		Subject:    sub,
		Username:   username,
		Expiration: exp,
	}
	// payload := fmt.Sprintf("{\"iss\": \"%s\" ,\"sub\": \"%s\", \"username\": \"%s\", \"exp\": %d}", issuer, sub, username, exp)
	payload, _ := json.Marshal(pld)
	enc_header := base64.RawURLEncoding.EncodeToString([]byte(header))
	enc_payload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	enc_sign := sign_string(fmt.Sprintf("%s.%s", enc_header, enc_payload))

	res := fmt.Sprintf("%s.%s.%s", enc_header, enc_payload, enc_sign)

	refresh := random_string(64)

	refresh_token := RefreshToken{
		Token:      refresh,
		Username:   username,
		Expiration: time.Now().Add(time.Hour * 24 * 7),
	}
	refresh_tokens[refresh] = refresh_token

	return res, refresh
}

func sign_string(input string) string {
	data := []byte(input)
	secret := get_secret()
	secret_byes := []byte(secret)
	signer := hmac.New(sha256.New, secret_byes)
	signer.Write(data)
	signature := signer.Sum(nil)
	enc_sign := base64.RawURLEncoding.EncodeToString(signature)
	return enc_sign
}

func TestToken(w http.ResponseWriter, r *http.Request) {
	headers := r.Header

	fmt.Println("Request Header:")
	for key, values := range headers {
		fmt.Printf("%s: %s\n", key, values)
	}

	bearerToken := headers.Get("Authorization")
	reqToken := strings.Split(bearerToken, " ")[1]

	//get partes
	parts := strings.Split(reqToken, ".")
	fmt.Println(parts)
	hdr := parts[0]
	pld := parts[1]
	sign := parts[2]

	content := fmt.Sprintf("%s.%s", hdr, pld)
	signed := sign_string(content)
	fmt.Printf("%s vs %s \n", sign, signed)
	if signed != sign {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	pld_bytes, _ := base64.RawURLEncoding.DecodeString(pld)
	var payload TokenPayload
	json.Unmarshal(pld_bytes, &payload)

	var pld_map map[string]interface{}
	json.Unmarshal(pld_bytes, &pld_map)
	fmt.Println(pld_map)

	username := pld_map["username"]
	// expire_num := pld_map["exp"].(int64)
	expire_num := payload.Expiration
	expire := time.Unix(expire_num, 0)

	fmt.Printf("token expires at %s\n", expire.String())
	if expire_num < time.Now().Unix() {
		w.WriteHeader(http.StatusUnauthorized)

		fmt.Fprintf(w, "token expired at %s", expire.String())
		return
	}

	fmt.Fprintf(w, "Ok for token: '%s', welcome '%s'", reqToken, username)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&input)
	fmt.Println(input)

	refresh_token := input["token"].(string)
	token, found := refresh_tokens[refresh_token]
	if !found {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if token.Expiration.Before(time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Refresh token expired")
		return
	}

	delete(refresh_tokens, refresh_token)

	new_token, new_refresh := new_jwt(token.Username)

	fmt.Fprintf(w, "{\"token\": \"%s\", \"refresh\": \"%s\"}", new_token, new_refresh)
}
