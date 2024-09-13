package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	tokenStore *TokenStore
)

type TokenInfo struct {
	ExpireAt time.Time
}

type TokenStore struct {
	tokens map[string]TokenInfo
	mutex  sync.RWMutex
}

func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]TokenInfo),
	}
}

func (ts *TokenStore) Set(tid string, info TokenInfo) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.tokens[tid] = info
}

func (ts *TokenStore) Get(tid string) (TokenInfo, bool) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	info, exists := ts.tokens[tid]
	return info, exists
}

func (ts *TokenStore) Delete(tid string) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	delete(ts.tokens, tid)
}

func generateTID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func init() {
	var err error
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgQCF0vHwbHxu6FFdin2m8I/8MoRhYYr86AZeAXRKYbECR/iZzzzIN9LU
fBaAQVXJtptlxUFj5MLxYQkfRjMY8G9MTHvCdqgkoQ0EloKpnR1Jm/S+Xyrxc6GK
yppH6MV2h4UZA8lM0JuZgQQzNytotEjbdP3a4DLUIzAOg4qpk76Kvw==
-----END RSA PRIVATE KEY-----`))
	if err != nil {
		panic(err)
	}
	publicKey = &privateKey.PublicKey

	tokenStore = NewTokenStore()
}

func main() {
	r := gin.Default()
	auth := r.Group("/auth")
	{
		auth.POST("/login", login)
		auth.POST("/logout", logout)
		auth.GET("/.well-known/jwks.json", jwks)
		auth.GET("/validate", validate)
	}
	r.Run(":8080")
}

func login(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Authenticate credentials (assumed)
	if credentials.Username != "user1" || credentials.Password != "password1" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate TID
	tid, err := generateTID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate TID"})
		return
	}

	// Create JWT
	expirationTime := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":      credentials.Username,
		"iss":      "auth-service",
		"iat":      time.Now().Unix(),
		"exp":      expirationTime.Unix(),
		"username": credentials.Username,
		"role":     "normal",
		"tid":      tid,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	// Store TID in memory
	tokenStore.Set(tid, TokenInfo{
		ExpireAt: expirationTime,
	})

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func logout(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}

	tokenString = tokenString[7:] // Remove "Bearer " prefix

	// Parse token to get TID
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not parse token claims"})
		return
	}

	tid, ok := claims["tid"].(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get TID from token"})
		return
	}

	// Remove TID from memory store
	tokenStore.Delete(tid)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func jwks(c *gin.Context) {
	n := base64.URLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.URLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "auth-key",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}

	c.JSON(http.StatusOK, jwks)
}

func validate(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	tokenString = tokenString[7:] // Remove "Bearer " prefix

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not parse token claims"})
		return
	}

	tid, ok := claims["tid"].(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get TID from token"})
		return
	}

	// Check TID in memory store
	tokenInfo, exists := tokenStore.Get(tid)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Check if token has expired
	if time.Now().After(tokenInfo.ExpireAt) {
		tokenStore.Delete(tid)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
		return
	}

	c.Header("x-current-user", claims["username"].(string))

	c.JSON(http.StatusOK, gin.H{
		"valid":    true,
		"username": claims["username"],
		"role":     claims["role"],
	})
}
