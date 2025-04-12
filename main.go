package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ilovemysocksmoree/adcore/internal/auth"
	"github.com/ilovemysocksmoree/adcore/internal/connection"
	"github.com/ilovemysocksmoree/adcore/internal/objects"
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
		fmt.Println("unable to get instance of authenticator")
		os.Exit(1)
		return
	}

	session, err := authenticator.Authenticate(userlogon, password, username)
	if err != nil {
		fmt.Printf("authentication failed: %v \n", err)
		os.Exit(1)
		return
	}

	fmt.Printf("Authentication successful, session-id: %s \n", session.ID)
	fmt.Printf("Session will expires at: %s \n", session.ExpiresAt.Format(time.RFC3339))

	ou := objects.NewOUManager(cm, baseDN)
	ous, err := ou.GetAllOUs(authConfig.BindUser, authConfig.BindPwd, nil, []string{})
	if err != nil {
		fmt.Println("error while getting all OUs")
	}

	fmt.Println("=======================================")
	for _, oui := range ous {
		fmt.Println(oui.DistinguishedName)
	}
	fmt.Println("=======================================")

	um := objects.NewUserManager(cm, baseDN)
	user1 := &objects.User{
		SAMAccountName:    "mane",
		DistinguishedName: "CN=sadio mane10,OU=Engineering, OU=ADS,DC=adscanner,DC=local",
		UserPrincipalName: "sadiooo11@adscanner.local",
		DisplayName:       "sadio mane",
		GivenName:         "sadio10",
		SurName:           "mane",
		Description:       "Software Engineer",
		Title:             "Senior Developer",
		Department:        "Engineering",
		Company:           "Example Corp",
		TelephoneNumber:   "+1-555-123-4567",
		Mobile:            "+1-555-987-6543",
		Memberof:          []string{},
		RawAttributes:     make(map[string][]string),
		WhenCreated:       time.Time{},
		WhenChanged:       time.Time{},
	}

	err = um.CreateUser(user1, "P@ssw0rd123!@#", authConfig.BindUser, authConfig.BindPwd)
	if err != nil {
		fmt.Printf("error while creating user: %v \n", err)
	}

	fmt.Println("User created successfully")
}
