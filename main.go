package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ilovemysocksmoree/adcore/internal/auth"
	"github.com/ilovemysocksmoree/adcore/internal/connection"
)

func main() {
	adServer := "ldap://192.168.1.8:389"
	baseDN := "DC=adscanner,DC=local"
	domain := "adscanner.local"
	username := "Administrator"
	userlogon := fmt.Sprintf("%s@%s", username, domain)
	password := "admin@123"

	cfg := connection.GetConnConfig(adServer)
	err := cfg.Validate()
	if err != nil {
		fmt.Println("invalid configuration provided")
		os.Exit(1)
	}

	cm := connection.GetConnectionManager(cfg)
	defer cm.Close()

	err = cm.CheckHealth()
	if err != nil {
		fmt.Println("connection health-check failed")
		os.Exit(1)
	}

	authConfig := auth.NewAuthDefaultConfig(baseDN)
	authenticator, err := auth.NewAuthenticator(cm, authConfig)
	if err != nil {
		fmt.Println("unable to get authenticator's instance")
		os.Exit(1)
		return
	}
	defer authenticator.Close()

	session, err := authenticator.Authenticate(userlogon, password, username)
	if err != nil {
		fmt.Printf("authentication failed: %v \n", err)
		os.Exit(1)
		return
	}

	fmt.Printf("Authentication successful, session-id: %s \n", session.ID)
	fmt.Printf("Session will expires at: %s \n", session.ExpiresAt.Format(time.RFC3339))

	userInfo, err := authenticator.GetUserInfo("ayid.admin2", authConfig.BindUser, authConfig.BindPwd)
	if err != nil {
		fmt.Printf("error while getting user info: %v \n", err)
	} else {
		fmt.Println("============================================")
		fmt.Printf("Display name: %s \n", userInfo.DisplayName)
		fmt.Printf("Username: %s \n", userInfo.Username)
		fmt.Printf("Email: %s \n", userInfo.Email)
		fmt.Printf("Members of group: %d \n", len(userInfo.Groups))

		fmt.Println("GROUPPP")
		for _, grp := range userInfo.Groups {
			fmt.Println(grp)
		}
		fmt.Println("GROUPPP")
		fmt.Println("============================================")
	}

	connStats := cm.GetStats()
	fmt.Println("Connection Stats")
	for k, v := range connStats {
		fmt.Printf("[%s]:> %s \n", k, v)
	}
}
