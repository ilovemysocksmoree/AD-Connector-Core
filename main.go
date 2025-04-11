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

	for _, oui := range ous {
		fmt.Println(oui)
	}
	// ou1 := &objects.OU{
	// 	Name:              "Sales",
	// 	DistinguishedName: "OU=Sales,DC=adscanner,DC=local",
	// 	Description:       "Organizational Unit for Sales Department",
	// 	RawAttributes:     make(map[string][]string),
	// }

	// ou2 := &objects.OU{
	// 	Name:              "Engineering-Team",
	// 	DistinguishedName: "OU=Engineering,OU=ADS,DC=adscanner,DC=local",
	// 	Description:       "Organizational Unit for Engineering Department",
	// 	RawAttributes:     make(map[string][]string),
	// }

	// if err := ou.CreateOU(ou2, authConfig.BindUser, authConfig.BindPwd); err != nil {
	// 	fmt.Println(err, "while creeating ou")
	// }

	// om := objects.NewGroupManager(cm, baseDN)
	// CN=ADSManagers,OU=ADS,DC=adscanner,DC=local
	// group1 := &objects.Group{
	// 	SAMAccountName:    "Bobthebuider",
	// 	DistinguishedName: "CN=Builders,OU=Engineering,OU=ADS,DC=adscanner,DC=local",
	// 	Name:              "Security Analyst Team",
	// 	DisplayName:       "Security Analyst Team",
	// 	Description:       "Group for security analysts",
	// 	Type:              objects.GroupTypeGlobal | objects.GroupTypeSecurity,
	// 	Email:             "secanalyst@adscanner.local",
	// 	Members:           []string{},
	// 	MemberOf:          []string{},
	// 	RawAttributes:     make(map[string][]string),
	// }

	// if err := om.CreateGroup(group1, authConfig.BindUser, authConfig.BindPwd); err != nil {
	// 	fmt.Println("error while creating new group", err)
	// }

	um := objects.NewUserManager(cm, baseDN)
	// test_user := "ayid.admin1"
	// user, err := um.GetUserBySAMAccountName(test_user, authConfig.BindUser, authConfig.BindPwd)
	// if err != nil {
	// 	fmt.Printf("unable to find user with given username: %s | err: %v \n", test_user, err)
	// }

	// users, _ := um.GetAllUsers(authConfig.BindUser, authConfig.BindPwd, nil, []string{})
	// for _, user := range users {
	// 	fmt.Println(user)
	// }

	user1 := &objects.User{
		SAMAccountName:    "sshereerr",
		DistinguishedName: "CN=bob,OU=Engineering,OU=ADS,DC=adscanner,DC=local",
		UserPrincipalName: "jdoe@adscanner.local",
		DisplayName:       "John Doe",
		GivenName:         "John",
		SurName:           "Doe",
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

	err = um.CreateUser(user1, "Admin@123!", authConfig.BindUser, authConfig.BindPwd)
	if err != nil {
		fmt.Printf("error while creating user: %v \n", err)
	}

	fmt.Println("User created successfully")

	// forestDiscovery := discovery.NewForestDiscovery(cm)
	// forestDiscovery.DiscoverForest(userlogon, password, baseDN)

	// if err != nil {
	// 	fmt.Println("unable to get authenticator's instance")
	// 	os.Exit(1)
	// 	return
	// }
	// defer authenticator.Close()

	// userInfo, err := authenticator.GetUserInfo("ayid.admin2", authConfig.BindUser, authConfig.BindPwd)
	// if err != nil {
	// 	fmt.Printf("error while getting user info: %v \n", err)
	// } else {
	// 	fmt.Println("============================================")
	// 	fmt.Printf("Display name: %s \n", userInfo.DisplayName)
	// 	fmt.Printf("Username: %s \n", userInfo.Username)
	// 	fmt.Printf("Email: %s \n", userInfo.Email)
	// 	fmt.Printf("Members of group: %d \n", len(userInfo.Groups))

	// 	fmt.Println("GROUPPP")
	// 	for _, grp := range userInfo.Groups {
	// 		fmt.Println(grp)
	// 	}
	// 	fmt.Println("GROUPPP")
	// 	fmt.Println("============================================")
	// }

	// connStats := cm.GetStats()
	// fmt.Println("Connection Stats")
	// for k, v := range connStats {
	// 	fmt.Printf("[%s]:> %s \n", k, v)
	// }
}
