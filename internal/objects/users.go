package objects

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/ilovemysocksmoree/adcore/internal/connection"
)

type UserAttribute string

const (
	UserAttrSAMAccountName     UserAttribute = "sAMAccountName"
	UserAttrUserPrincipalName  UserAttribute = "userPrincipalName"
	UserAttrDisplayName        UserAttribute = "displayName"
	UserAttrGivenName          UserAttribute = "givenName"
	UserAttrSurname            UserAttribute = "sn"
	UserAttrMail               UserAttribute = "mail"
	UserAttrDescription        UserAttribute = "description"
	UserAttrMemberOf           UserAttribute = "memberOf"
	UserAttrObjectGUID         UserAttribute = "objectGUID"
	UserAttrObjectSID          UserAttribute = "objectSID"
	UserAttrWhenCreated        UserAttribute = "whenCreated"
	UserAttrWhenChanged        UserAttribute = "whenChanged"
	UserAttrLastLogon          UserAttribute = "lastLogon"
	UserAttrLastLogonTimestamp UserAttribute = "lastLogonTimestamp"
	UserAttrPwdLastSet         UserAttribute = "pwdLastSet"
	UserAttrUserAccountControl UserAttribute = "userAccountControl"
	UserAttrAccountExpires     UserAttribute = "accountExpires"
	UserAttrDistinguishedName  UserAttribute = "distinguishedName"
	UserAttrTitle              UserAttribute = "title"
	UserAttrDepartment         UserAttribute = "department"
	UserAttrCompany            UserAttribute = "company"
	UserAttrTelephoneNumber    UserAttribute = "telephoneNumber"
	UserAttrMobile             UserAttribute = "mobile"
	UserAttrManager            UserAttribute = "manager"
)

type UserAccountControlFlag uint32

const (
	UAC_SCRIPT                         UserAccountControlFlag = 0x0001
	UAC_ACCOUNTDISABLE                 UserAccountControlFlag = 0x0002
	UAC_HOMEDIR_REQUIRED               UserAccountControlFlag = 0x0008
	UAC_LOCKOUT                        UserAccountControlFlag = 0x0010
	UAC_PASSWD_NOTREQD                 UserAccountControlFlag = 0x0020
	UAC_PASSWD_CANT_CHANGE             UserAccountControlFlag = 0x0040
	UAC_ENCRYPTED_TEXT_PWD_ALLOWED     UserAccountControlFlag = 0x0080
	UAC_TEMP_DUPLICATE_ACCOUNT         UserAccountControlFlag = 0x0100
	UAC_NORMAL_ACCOUNT                 UserAccountControlFlag = 0x0200
	UAC_INTERDOMAIN_TRUST_ACCOUNT      UserAccountControlFlag = 0x0800
	UAC_WORKSTATION_TRUST_ACCOUNT      UserAccountControlFlag = 0x1000
	UAC_SERVER_TRUST_ACCOUNT           UserAccountControlFlag = 0x2000
	UAC_DONT_EXPIRE_PASSWORD           UserAccountControlFlag = 0x10000
	UAC_MNS_LOGON_ACCOUNT              UserAccountControlFlag = 0x20000
	UAC_SMARTCARD_REQUIRED             UserAccountControlFlag = 0x40000
	UAC_TRUSTED_FOR_DELEGATION         UserAccountControlFlag = 0x80000
	UAC_NOT_DELEGATED                  UserAccountControlFlag = 0x100000
	UAC_USE_DES_KEY_ONLY               UserAccountControlFlag = 0x200000
	UAC_DONT_REQ_PREAUTH               UserAccountControlFlag = 0x400000
	UAC_PASSWORD_EXPIRED               UserAccountControlFlag = 0x800000
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION UserAccountControlFlag = 0x1000000
	UAC_PARTIAL_SECRETS_ACCOUNT        UserAccountControlFlag = 0x04000000
)

type User struct {
	SAMAccountName    string
	UserPrincipalName string
	DisplayName       string
	GivenName         string
	SurName           string
	Mail              string
	Description       string
	Memberof          []string
	ObjectGUID        string
	ObjectSID         string

	WhenCreated        time.Time
	WhenChanged        time.Time
	LastLogon          int64
	LastLogonTimestamp int64
	PwdLastSet         int64

	UserAccountControl uint32
	AccountExpires     int64

	DistinguishedName string
	Title             string
	Department        string
	Company           string
	Manager           string
	TelephoneNumber   string
	Mobile            string

	RawAttributes map[string][]string
}

type UserManager struct {
	conn   *connection.Manager
	baseDN string
}

func NewUserManager(conn *connection.Manager, baseDN string) *UserManager {
	return &UserManager{
		conn:   conn,
		baseDN: baseDN,
	}
}

// fetch all user object ad-forest
func (um *UserManager) GetAllUsers(bindUser, bindPassword string, page *int, attr []string) ([]*User, error) {
	p := 10
	if page != nil {
		p = *page
	}

	fmt.Println(p)

	if len(attr) == 0 {
		attr = defaultUserAttr()
	}

	req := ldap.NewSearchRequest(
		um.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(objectCategory=person))",
		attr,
		nil,
	)

	resp, err := um.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("entry is empty while getting all users")
	}

	var users []*User
	for _, ent := range resp.Entries {
		user := um.entryToUser(ent)
		if user != nil {
			users = append(users, user)
		}
	}

	if len(users) == 0 {
		fmt.Printf("users not found for domain: %s \n", um.baseDN)
	}

	return users, nil
}

func (um *UserManager) GetUserBySAMAccountName(username, bindUser, bindPassword string) (*User, error) {
	searchFilter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(sAMAccountName=%s))", ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		um.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		defaultUserAttr(),
		nil,
	)

	resp, err := um.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, err
	}

	fmt.Println(resp)
	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("search response entry is zero")
	}

	if len(resp.Entries) > 1 {
		fmt.Println("same SAMAccountName found for more than one user")
	}

	user := um.entryToUser(resp.Entries[0])
	return user, nil
}

func (um *UserManager) GetUserByDN(dn, bindUser, bindPassword string) (*User, error) {
	req := ldap.NewSearchRequest(
		um.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		defaultUserAttr(),
		nil,
	)

	resp, err := um.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("search response entry is zero")
	}

	if len(resp.Entries) > 1 {
		fmt.Println("same distinugished name found for more than one user")
	}

	user := um.entryToUser(resp.Entries[0])
	return user, nil
}

func (um *UserManager) FindUsers(filter, bindUser, bindPassword string, attr []string) ([]*User, error) {
	if len(attr) == 0 {
		attr = defaultUserAttr()
	}

	if !strings.HasPrefix(filter, "(&") && !strings.HasPrefix(filter, "(|") && !strings.HasPrefix(filter, "(") {
		filter = fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(%s))", filter)
	}

	req := ldap.NewSearchRequest(
		um.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attr,
		nil,
	)

	resp, err := um.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("search response entry is zero")
	}

	parseUser := make([]*User, 0, len(resp.Entries))
	for _, ent := range resp.Entries {
		u := um.entryToUser(ent)
		parseUser = append(parseUser, u)
	}

	return parseUser, nil
}

func (um *UserManager) CreateUser(user *User, password, bindUser, bindPassword string) error {
	fmt.Println("Adding user:")
	fmt.Println(user)

	if user.SAMAccountName == "" {
		return fmt.Errorf("this is required field, please add SAMAccountName")
	}

	if user.DistinguishedName == "" {
		return fmt.Errorf("this is required field, please add unique name")
	}

	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "person", "organizationalPerson", "user"}},
		{Type: "sAMAccountName", Vals: []string{user.SAMAccountName}},
	}

	if user.UserPrincipalName != "" {
		attrs = append(attrs, ldap.Attribute{Type: "userPrincipalName", Vals: []string{user.UserPrincipalName}})
	}
	if user.DisplayName != "" {
		attrs = append(attrs, ldap.Attribute{Type: "displayName", Vals: []string{user.DisplayName}})
	}
	if user.GivenName != "" {
		attrs = append(attrs, ldap.Attribute{Type: "givenName", Vals: []string{user.GivenName}})
	}
	if user.SurName != "" {
		attrs = append(attrs, ldap.Attribute{Type: "sn", Vals: []string{user.SurName}})
	}
	if user.Mail != "" {
		attrs = append(attrs, ldap.Attribute{Type: "mail", Vals: []string{user.Mail}})
	}
	if user.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: "description", Vals: []string{user.Description}})
	}
	if user.Title != "" {
		attrs = append(attrs, ldap.Attribute{Type: "title", Vals: []string{user.Title}})
	}
	if user.Department != "" {
		attrs = append(attrs, ldap.Attribute{Type: "department", Vals: []string{user.Department}})
	}
	if user.Company != "" {
		attrs = append(attrs, ldap.Attribute{Type: "company", Vals: []string{user.Company}})
	}
	if user.TelephoneNumber != "" {
		attrs = append(attrs, ldap.Attribute{Type: "telephoneNumber", Vals: []string{user.TelephoneNumber}})
	}
	if user.Mobile != "" {
		attrs = append(attrs, ldap.Attribute{Type: "mobile", Vals: []string{user.Mobile}})
	}

	intialUAC := uint32(UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE | UAC_PASSWD_NOTREQD)
	attrs = append(attrs, ldap.Attribute{
		Type: "userAccountControl",
		Vals: []string{fmt.Sprintf("%d", intialUAC)},
	})

	req := ldap.NewAddRequest(user.DistinguishedName, nil)
	req.Attributes = attrs

	conn, err := um.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return err
	}
	defer um.conn.ReleaseConnection(conn)

	resp := conn.Add(req)
	if resp != nil {
		return fmt.Errorf("unable to create new user: %v", resp)
	}

	if password != "" {
		if err := um.SetPassword(user.DistinguishedName, password, bindUser, bindPassword); err != nil {
			fmt.Println("unable to change password")
			return err
		}

		newModifyReq := ldap.NewModifyRequest(user.DistinguishedName, nil)
		enabledUAC := uint32(UAC_NORMAL_ACCOUNT)
		newModifyReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", enabledUAC)})

		if err := conn.Modify(newModifyReq); err != nil {
			return fmt.Errorf("user created with password but failed to enabled about: %w", err)
		}
	}

	fmt.Printf("User created successfully \n")
	return nil
}

func (um *UserManager) DeleteUser(dn, bindUser, bindPassword string) error {
	req := ldap.NewDelRequest(dn, nil)

	resp := um.conn.Delete(bindUser, bindPassword, req)
	if resp != nil {
		return fmt.Errorf("[DELETE:USER] > %v", resp)
	}

	return nil
}

func (um *UserManager) SetPassword(dn, password, bindUser, bindPassword string) error {
	conn, err := um.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return err
	}
	defer um.conn.ReleaseConnection(conn)

	quotoPwd := fmt.Sprintf("\"%s\"", password)
	encodedPwd := utf16LittleEndianEncode(quotoPwd)

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{encodedPwd})

	if err := conn.Modify(mod); err != nil {
		fmt.Println("error while modifying password")
		return err
	}

	return nil
}

func (um *UserManager) entryToUser(u *ldap.Entry) *User {
	user := &User{
		RawAttributes: make(map[string][]string),
	}

	for _, attr := range u.Attributes {
		user.RawAttributes[attr.Name] = attr.Values
	}

	getSingleValue := func(attr string) string {
		v := u.GetAttributeValue(attr)
		if len(v) > 0 {
			return v
		}

		return ""
	}

	parseTime := func(t string) time.Time {
		if t == "" {
			return time.Time{}
		}

		newTime, err := time.Parse("20060102150405.0Z", t)
		if err != nil {
			return time.Time{}
		}

		return newTime
	}

	parseInt64 := func(v string) int64 {
		if v == "" {
			return 0
		}

		var holder int64
		_, err := fmt.Sscanf(v, "%d", &holder)
		if err != nil {
			return 0
		}

		return holder
	}

	user.SAMAccountName = getSingleValue(string(UserAttrSAMAccountName))
	user.UserPrincipalName = getSingleValue(string(UserAttrUserPrincipalName))
	user.DisplayName = getSingleValue(string(UserAttrDisplayName))
	user.GivenName = getSingleValue(string(UserAttrGivenName))
	user.SurName = getSingleValue(string(UserAttrSurname))
	user.Mail = getSingleValue(string(UserAttrMail))
	user.Description = getSingleValue(string(UserAttrDescription))
	user.ObjectGUID = getSingleValue(string(UserAttrObjectGUID))
	user.ObjectSID = getSingleValue(string(UserAttrObjectSID))
	user.DistinguishedName = getSingleValue(string(UserAttrDistinguishedName))
	user.Title = getSingleValue(string(UserAttrTitle))
	user.Department = getSingleValue(string(UserAttrDepartment))
	user.Company = getSingleValue(string(UserAttrCompany))
	user.Manager = getSingleValue(string(UserAttrManager))
	user.TelephoneNumber = getSingleValue(string(UserAttrTelephoneNumber))
	user.Mobile = getSingleValue(string(UserAttrMobile))
	user.Memberof = u.GetAttributeValues(string(UserAttrMemberOf))
	user.WhenCreated = parseTime(getSingleValue(string(UserAttrWhenCreated)))
	user.WhenChanged = parseTime(getSingleValue(string(UserAttrWhenChanged)))
	user.LastLogon = parseInt64(getSingleValue(string(UserAttrLastLogon)))
	user.LastLogonTimestamp = parseInt64(getSingleValue(string(UserAttrLastLogonTimestamp)))
	user.PwdLastSet = parseInt64(getSingleValue(string(UserAttrPwdLastSet)))
	user.AccountExpires = parseInt64(getSingleValue(string(UserAttrAccountExpires)))

	uacStr := getSingleValue(string(UserAttrUserAccountControl))
	if uacStr != "" {
		var uac uint32
		_, err := fmt.Sscanf(uacStr, "%d", &uac)
		if err == nil {
			user.UserAccountControl = uac
		}
	}

	return user
}

func utf16LittleEndianEncode(s string) string {
	runes := []rune(s)
	utf16bytes := make([]byte, len(runes)*2)

	for i, r := range runes {
		utf16bytes[i*2] = byte(r)
		utf16bytes[i*2+1] = byte(r >> 8)
	}
	return string(utf16bytes)
}

// func (um *UserManager) setBaseDN(baseDN string) {
// 	um.baseDN = baseDN
// }

func defaultUserAttr() []string {
	return []string{
		string(UserAttrSAMAccountName),
		string(UserAttrUserPrincipalName),
		string(UserAttrDisplayName),
		string(UserAttrGivenName),
		string(UserAttrSurname),
		string(UserAttrMail),
		string(UserAttrDescription),
		string(UserAttrMemberOf),
		string(UserAttrObjectGUID),
		string(UserAttrObjectSID),
		string(UserAttrWhenCreated),
		string(UserAttrWhenChanged),
		string(UserAttrLastLogon),
		string(UserAttrLastLogonTimestamp),
		string(UserAttrPwdLastSet),
		string(UserAttrUserAccountControl),
		string(UserAttrAccountExpires),
		string(UserAttrDistinguishedName),
		string(UserAttrTitle),
		string(UserAttrDepartment),
		string(UserAttrCompany),
		string(UserAttrTelephoneNumber),
		string(UserAttrMobile),
		string(UserAttrManager),
	}
}
