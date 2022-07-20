package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/go-ldap/ldap/v3"
	. "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/pingcap/errors"
)

var AUTH_LDAP = "auth_ldap"

func NewConnLdapAuth(conn net.Conn, serverConf *Server, l Ldap, h Handler) (*Conn, error) {
	var packetConn *packet.Conn
	if serverConf.tlsConfig != nil {
		packetConn = packet.NewTLSConn(conn)
	} else {
		packetConn = packet.NewConn(conn)
	}

	salt := RandomBuf(20)

	c := &Conn{
		Conn:         packetConn,
		serverConf:   serverConf,
		h:            h,
		connectionID: atomic.AddUint32(&baseConnID, 1),
		stmts:        make(map[uint32]*Stmt),
		salt:         salt,
		Ldap:         l,
	}
	c.closed.Set(false)

	if err := c.handshake(); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

func (c *Conn) compareLdapAuthData(clientAuthData []byte) error {
	_, err := LdapContent(&c.Ldap, c.user, string(clientAuthData), false)
	return err
}

type Ldap struct {
	Url      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
	Type     string `json:"type"`
	Sc       string `json:"sc"`
	Ldaps    bool   `json:"ldaps"`
}

func LdapContent(l *Ldap, user string, pass string, isTest bool) (isOk bool, err error) {

	var ld *ldap.Conn

	if l.Ldaps {
		ld, err = ldap.DialTLS("tcp", l.Url, &tls.Config{InsecureSkipVerify: true})
	} else {
		ld, err = ldap.Dial("tcp", l.Url)
	}

	if err != nil {
		return false, err
	}

	defer ld.Close()

	if ld != nil {
		if err := ld.Bind(l.User, l.Password); err != nil {
			return false, err
		}
		if isTest {
			return true, nil
		}

	}

	searchRequest := ldap.NewSearchRequest(
		l.Sc,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(l.Type, user),
		[]string{"dn"},
		nil,
	)

	sr, err := ld.Search(searchRequest)

	if err != nil {
		return false, err
	}

	if len(sr.Entries) != 1 {
		return false, errors.New("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	if err := ld.Bind(userdn, pass); err != nil {
		return false, err
	}
	return true, nil
}
