package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var projects = map[string][]string{
	"user1": {"Project A", "Project B"},
	"user2": {"Project C", "Project D"},
}

func main() {
	r := gin.Default()

	r.GET("/projects/headers", func(c *gin.Context) {
		headers := make(map[string][]string)
		for name, values := range c.Request.Header {
			headers[name] = values
		}
		c.JSON(http.StatusOK, gin.H{"headers": headers})
	})

	r.Use(jwtMiddleware())

	r.GET("/projects", getProjects)

	r.Run(":8080")
}

func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// In ra tất cả các header
		fmt.Println("All Headers:")
		for key, values := range c.Request.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		tokenString := bearerToken[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ở đây, bạn nên xác thực issuer và lấy public key từ JWKS endpoint
			// Để đơn giản, chúng ta sẽ sử dụng một public key cố định
			return jwt.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----`))
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			username, ok := claims["sub"].(string)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
				c.Abort()
				return
			}
			c.Set("username", username)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func getProjects(c *gin.Context) {
	username, _ := c.Get("username")
	fmt.Printf("User requesting projects: %v\n", username)

	userProjects, ok := projects[username.(string)]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "No projects found for user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"projects": userProjects})
}
