/*
Copyright IBM Corp. 2019 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"log"
    "os"
	"strconv"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

var Info  = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
var Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

// SimpleChaincode example simple Chaincode implementation using private data.
type SimpleChaincode struct {
}

// Init initializes the chaincode state
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	Info.Println("########### private_data_cc Init ###########")

	return shim.Success(nil)

}

// Invoke makes payment of X units from A to B
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	Info.Println("########### private_data_cc Invoke ###########")

	function, args := stub.GetFunctionAndParameters()

	Info.Println("invoke function: " + function)

	if function == "query" {
		// queries an entity state
		return t.query(stub, args)
	}

	if function == "move" {
		// Deletes an entity from its state
		return t.move(stub, args)
	}

	if function == "set" {
		// Sets an entity from its state
		return t.set(stub, args)
	}

	Error.Printf("Unknown action, check the first argument, must be one of 'delete', 'query', or 'move'. But got: %v", args[0])
	return shim.Error(fmt.Sprintf("Unknown action, check the first argument, must be one of 'delete', 'query', or 'move'. But got: %v", args[0]))
}

func (t *SimpleChaincode) move(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// must be an invoke
	var A, B string    // Entities
	var Aval, Bval int // Asset holdings
	var X int          // Transaction value
	var err error

	if len(args) != 0 {
    		return shim.Error("Incorrect number of arguments. All attributes must be included in the transient map.")
    }

    transMap, err := stub.GetTransient()
    	if err != nil {
    		return shim.Error("Error getting transient: " + err.Error())
    }

    if len(transMap) !=3 {
		return shim.Error("Incorrect number of arguments. Expecting 3, function followed by 2 names and 1 value, got " + strconv.Itoa(len(transMap)))
	}

	A = string(transMap["A"])
	B = string(transMap["B"])

	// Get the state from the ledger
	// TODO: will be nice to have a GetAllState call to ledger
	Avalbytes, err := stub.GetPrivateData("COLLECTION_FOR_A", A)
	if err != nil {
		return shim.Error("Failed to get state")
	}
	if Avalbytes == nil {
		return shim.Error("Entity not found")
	}
	Aval, _ = strconv.Atoi(string(Avalbytes))

	Bvalbytes, err := stub.GetPrivateData("COLLECTION_FOR_B", B)
	if err != nil {
		return shim.Error("Failed to get state")
	}
	if Bvalbytes == nil {
		return shim.Error("Entity not found")
	}
	Bval, _ = strconv.Atoi(string(Bvalbytes))

	// Perform the execution
	X, err = strconv.Atoi(string(transMap["moveAmount"]))
	if err != nil {
		return shim.Error("Invalid transaction amount, expecting a integer value")
	}
	Aval = Aval - X
	Bval = Bval + X
	Info.Printf("Aval = %d, Bval = %d\n", Aval, Bval)

	// Write the state back to the ledger
	err = stub.PutPrivateData("COLLECTION_FOR_A", A, []byte(strconv.Itoa(Aval)))
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutPrivateData("COLLECTION_FOR_B", B, []byte(strconv.Itoa(Bval)))
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) set(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// must be an invoke
	var A, B string    // Entities
	var Aval, Bval int // Asset holdings
	var err error

	if len(args) != 0 {
		return shim.Error("Incorrect number of arguments. All attributes must be included in the transient map.")
	}

	transMap, err := stub.GetTransient()
	if err != nil {
		return shim.Error("Error getting transient: " + err.Error())
	}

	if len(transMap) !=4 {
		return shim.Error("Incorrect number of arguments. Expecting 4, function followed by 2 names and 2 values, got " + strconv.Itoa(len(transMap)))
	}

	A = string(transMap["A"])
	Aval, err = strconv.Atoi(string(transMap["AVal"]))
    if err != nil {
        return shim.Error("Invalid A value amount, expecting a integer value")
    }

	B = string(transMap["B"])
	Bval, err = strconv.Atoi(string(transMap["BVal"]))
    if err != nil {
       return shim.Error("Invalid B value amount, expecting a integer value")
    }

    Info.Printf("set %s = %d, %s = %d\n", A, Aval, B, Bval)

	// Perform the execution

	// Write the state back to the ledger
	err = stub.PutPrivateData("COLLECTION_FOR_A", A, []byte(strconv.Itoa(Aval)))
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutPrivateData("COLLECTION_FOR_B", B, []byte(strconv.Itoa(Bval)))
	if err != nil {
		return shim.Error(err.Error())
	}

	Info.Printf("set done %s = %d, %s = %d\n", A, Aval, B, Bval)

	return shim.Success(nil)
}

// Query callback representing the query of a chaincode ===>>>  ONLY Query B VALUES
func (t *SimpleChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	var QueryKey string // Entities
	var err error

	if len(args) != 0 {
		return shim.Error("Incorrect number of arguments. All attributes must be included in the transient map.")
	}

	transMap, err := stub.GetTransient()
		if err != nil {
			return shim.Error("Error getting transient: " + err.Error())
	}

	if len(transMap) !=1 {
		return shim.Error("Incorrect number of arguments. Expecting 1, function followed by query key, got " + strconv.Itoa(len(transMap)))
	}

	QueryKey = string(transMap["B"])

	Info.Printf("query for  %s\n", QueryKey)

	// Get the state from the ledger
	Avalbytes, err := stub.GetPrivateData("COLLECTION_FOR_B", QueryKey)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + QueryKey + "\"}"
		return shim.Error(jsonResp)
	}

	if Avalbytes == nil {
		jsonResp := "{\"Error\":\"Nil amount for " + QueryKey + "\"}"
		return shim.Error(jsonResp)
	}

	jsonResp := "{\"Name\":\"" + QueryKey + "\",\"Amount\":\"" + string(Avalbytes) + "\"}"
	Info.Printf("Query Response:%s\n", jsonResp)
	return shim.Success(Avalbytes)
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		Error.Printf("Error starting Simple chaincode: %s", err)
	}
}
