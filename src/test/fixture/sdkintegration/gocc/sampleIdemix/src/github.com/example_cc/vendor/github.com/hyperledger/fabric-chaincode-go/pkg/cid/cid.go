// Copyright the Hyperledger Fabric contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/pkg/attrmgr"
	"github.com/hyperledger/fabric-protos-go/msp"
)

// GetID returns the ID associated with the invoking identity.  This ID
// is guaranteed to be unique within the MSP.
func GetID(stub ChaincodeStubInterface) (string, error) {
	c, err := New(stub)
	if err != nil {
		return "", err
	}
	return c.GetID()
}

// GetMSPID returns the ID of the MSP associated with the identity that
// submitted the transaction
func GetMSPID(stub ChaincodeStubInterface) (string, error) {
	c, err := New(stub)
	if err != nil {
		return "", err
	}
	return c.GetMSPID()
}

// GetAttributeValue returns value of the specified attribute
func GetAttributeValue(stub ChaincodeStubInterface, attrName string) (value string, found bool, err error) {
	c, err := New(stub)
	if err != nil {
		return "", false, err
	}
	return c.GetAttributeValue(attrName)
}

// AssertAttributeValue checks to see if an attribute value equals the specified value
func AssertAttributeValue(stub ChaincodeStubInterface, attrName, attrValue string) error {
	c, err := New(stub)
	if err != nil {
		return err
	}
	return c.AssertAttributeValue(attrName, attrValue)
}

// HasOUValue checks if an OU with the specified value is present
func HasOUValue(stub ChaincodeStubInterface, OUValue string) (bool, error) {
	c, err := New(stub)
	if err != nil {
		return false, err
	}
	return c.HasOUValue(OUValue)
}

// GetX509Certificate returns the X509 certificate associated with the client,
// or nil if it was not identified by an X509 certificate.
func GetX509Certificate(stub ChaincodeStubInterface) (*x509.Certificate, error) {
	c, err := New(stub)
	if err != nil {
		return nil, err
	}
	return c.GetX509Certificate()
}

// ClientID holds the information of the transaction creator.
type ClientID struct {
	stub  ChaincodeStubInterface
	mspID string
	cert  *x509.Certificate
	attrs *attrmgr.Attributes
}

// New returns an instance of ClientID
func New(stub ChaincodeStubInterface) (*ClientID, error) {
	c := &ClientID{stub: stub}
	err := c.init()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// GetID returns a unique ID associated with the invoking identity.
func (c *ClientID) GetID() (string, error) {
	// When IdeMix, c.cert is nil for x509 type
	// Here will return "", as there is no x509 type cert for generate id value with logic below.
	if c.cert == nil {
		return "", fmt.Errorf("cannot determine identity")
	}
	// The leading "x509::" distinguishes this as an X509 certificate, and
	// the subject and issuer DNs uniquely identify the X509 certificate.
	// The resulting ID will remain the same if the certificate is renewed.
	id := fmt.Sprintf("x509::%s::%s", getDN(&c.cert.Subject), getDN(&c.cert.Issuer))
	return base64.StdEncoding.EncodeToString([]byte(id)), nil
}

// GetMSPID returns the ID of the MSP associated with the identity that
// submitted the transaction
func (c *ClientID) GetMSPID() (string, error) {
	return c.mspID, nil
}

// GetAttributeValue returns value of the specified attribute
func (c *ClientID) GetAttributeValue(attrName string) (value string, found bool, err error) {
	if c.attrs == nil {
		return "", false, nil
	}
	return c.attrs.Value(attrName)
}

// AssertAttributeValue checks to see if an attribute value equals the specified value
func (c *ClientID) AssertAttributeValue(attrName, attrValue string) error {
	val, ok, err := c.GetAttributeValue(attrName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("attribute '%s' was not found", attrName)
	}
	if val != attrValue {
		return fmt.Errorf("attribute '%s' equals '%s', not '%s'", attrName, val, attrValue)
	}
	return nil
}

// HasOUValue checks if an OU with the specified value is present
func (c *ClientID) HasOUValue(OUValue string) (bool, error) {
	x509Cert := c.cert
	if x509Cert == nil {
		// Here it will return false and an error, as there is no x509 type cert to check for OU values.
		return false, fmt.Errorf("cannot obtain an X509 certificate for the identity")
	}

	for _, OU := range x509Cert.Subject.OrganizationalUnit {
		if OU == OUValue {
			return true, nil
		}
	}
	return false, nil
}

// GetX509Certificate returns the X509 certificate associated with the client,
// or nil if it was not identified by an X509 certificate.
func (c *ClientID) GetX509Certificate() (*x509.Certificate, error) {
	return c.cert, nil
}

// Initialize the client
func (c *ClientID) init() error {
	signingID, err := c.getIdentity()
	if err != nil {
		return err
	}
	c.mspID = signingID.GetMspid()
	idbytes := signingID.GetIdBytes()
	block, _ := pem.Decode(idbytes)
	if block == nil {
		err := c.getAttributesFromIdemix()
		if err != nil {
			return fmt.Errorf("identity bytes are neither X509 PEM format nor an idemix credential: %s", err)
		}
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %s", err)
	}
	c.cert = cert
	attrs, err := attrmgr.New().GetAttributesFromCert(cert)
	if err != nil {
		return fmt.Errorf("failed to get attributes from the transaction invoker's certificate: %s", err)
	}
	c.attrs = attrs
	return nil
}

// Unmarshals the bytes returned by ChaincodeStubInterface.GetCreator method and
// returns the resulting msp.SerializedIdentity object
func (c *ClientID) getIdentity() (*msp.SerializedIdentity, error) {
	sid := &msp.SerializedIdentity{}
	creator, err := c.stub.GetCreator()
	if err != nil || creator == nil {
		return nil, fmt.Errorf("failed to get transaction invoker's identity from the chaincode stub: %s", err)
	}
	err = proto.Unmarshal(creator, sid)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction invoker's identity: %s", err)
	}
	return sid, nil
}

func (c *ClientID) getAttributesFromIdemix() error {
	creator, err := c.stub.GetCreator()
	attrs, err := attrmgr.New().GetAttributesFromIdemix(creator)
	if err != nil {
		return fmt.Errorf("failed to get attributes from the transaction invoker's idemix credential: %s", err)
	}
	c.attrs = attrs
	return nil
}

// Get the DN (distinguished name) associated with a pkix.Name.
// NOTE: This code is almost a direct copy of the String() function in
// https://go-review.googlesource.com/c/go/+/67270/1/src/crypto/x509/pkix/pkix.go#26
// which returns a DN as defined by RFC 2253.
func getDN(name *pkix.Name) string {
	r := name.ToRDNSequence()
	s := ""
	for i := 0; i < len(r); i++ {
		rdn := r[len(r)-1-i]
		if i > 0 {
			s += ","
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}
			typeString := tv.Type.String()
			typeName, ok := attributeTypeNames[typeString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += typeString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}
				typeName = typeString
			}
			valueString := fmt.Sprint(tv.Value)
			escaped := ""
			begin := 0
			for idx, c := range valueString {
				if (idx == 0 && (c == ' ' || c == '#')) ||
					(idx == len(valueString)-1 && c == ' ') {
					escaped += valueString[begin:idx]
					escaped += "\\" + string(c)
					begin = idx + 1
					continue
				}
				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escaped += valueString[begin:idx]
					escaped += "\\" + string(c)
					begin = idx + 1
				}
			}
			escaped += valueString[begin:]
			s += typeName + "=" + escaped
		}
	}
	return s
}

var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}
