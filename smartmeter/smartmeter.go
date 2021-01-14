package main

import (
	"fmt"
	"strconv"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"math/big"
	"psa/psa"
)

const num_clients int = 100
const num_labels int = 1
const max_value int = 100000000
const bound = num_clients * max_value

func dmcfe() {
    clients := make([]*fullysec.DMCFEClient, num_clients)
    public_keys := make([]*bn256.G1, num_clients)
    ciphertexts := make([]*bn256.G1, num_clients)
    key_shares := make([]data.VectorG2, num_clients)
    y := data.NewConstantVector(num_clients, big.NewInt(1))
    
    fmt.Println("----------------------------------------------------------------------------\n")
    fmt.Println("Running DMCFE scheme:")

    fmt.Printf("Creating %v clients\n", num_clients)
    for i := 0; i < num_clients; i++ {
        new_client, err := fullysec.NewDMCFEClient(i)
        if err != nil {
            fmt.Println(err)
            return
        }
        clients[i] = new_client
        public_keys[i] = clients[i].ClientPubKey
    }
    
    fmt.Println("Letting clients compute shared secrets")
    for i := 0; i < num_clients; i++ {
        err := clients[i].SetShare(public_keys)
        if err != nil {
            fmt.Println(err)
            return
        }
    }
    
    fmt.Println("Collecting key shares")
    for i := 0; i < num_clients; i++ {
        var err2 error
        key_shares[i], err2 = clients[i].DeriveKeyShare(y)
        if err2 != nil {
            fmt.Println(err2)
            return
        }
    }
    
    fmt.Printf("Starting protocol for %v labels\n", num_labels)
    for l := 0; l < num_labels; l++ {
        fmt.Println("Creating random plaintexts between 0 and ", max_value)
        plaintexts, err := data.NewRandomVector(num_clients, sample.NewUniform(big.NewInt(int64(max_value))))
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("Smartmeter: Encrypting plaintexts for label %v\n", strconv.Itoa(l))
        for i := 0; i < num_clients; i++ {
            ciphertexts[i], err = clients[i].Encrypt(plaintexts[i], strconv.Itoa(l))
            if err != nil {
                fmt.Println(err)
                return
            }
        }
        
        fmt.Printf("Power supplier: Decrypting ciphertexts for label %v\n", strconv.Itoa(l))
        power_consumption, err2 := fullysec.DMCFEDecrypt(ciphertexts, key_shares, y, strconv.Itoa(l), big.NewInt(int64(bound)))
        if err2 != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("Total power consumption: %v mWh\n", power_consumption)
    }
}



func main() {
    clients := make([]*psa.PSAClient, num_clients)
    public_keys := make([]*bn256.G1, num_clients)
    ciphertexts := make([]*big.Int, num_clients)
    key_shares := make([]data.Vector, num_clients)
    y := data.NewConstantVector(num_clients, big.NewInt(1))
    
    fmt.Println("----------------------------------------------------------------------------\n")
    fmt.Println("Running PSA scheme:")

    fmt.Printf("Creating %v clients\n", num_clients)
    for i := 0; i < num_clients; i++ {
        new_client, err := psa.NewPSAClient(i)
        if err != nil {
            fmt.Println(err)
            return
        }
        clients[i] = new_client
        public_keys[i] = clients[i].ClientPubKey
    }
    
    fmt.Println("Letting clients compute shared secrets")
    for i := 0; i < num_clients; i++ {
        err := clients[i].SetShare(public_keys)
        if err != nil {
            fmt.Println(err)
            return
        }
    }
    
    fmt.Println("Creating key shares")
    for i := 0; i < num_clients; i++ {
        var err2 error
        key_shares[i], err2 = clients[i].DeriveKeyShare(y)
        if err2 != nil {
            fmt.Println(err2)
            return
        }
    }
    
    fmt.Printf("Starting protocol for %v labels\n", num_labels)
    for l := 0; l < num_labels; l++ {
        fmt.Println("Creating random plaintexts between 0 and ", max_value)
        plaintexts, err := data.NewRandomVector(num_clients, sample.NewUniform(big.NewInt(int64(max_value))))
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("Smartmeter: Encrypting plaintexts for label %v\n", strconv.Itoa(l))
        for i := 0; i < num_clients; i++ {
            ciphertexts[i], err = clients[i].Encrypt(plaintexts[i], strconv.Itoa(l), num_clients)
            if err != nil {
                fmt.Println(err)
                return
            }
        }
        fmt.Printf("Power supplier: Decrypting ciphertexts for label %v\n", strconv.Itoa(l))
        power_consumption, err2 := psa.PSADecrypt(ciphertexts, key_shares, strconv.Itoa(l), num_clients)
        if err2 != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("Total power consumption: %v mWh\n", power_consumption)
    }
    
    dmcfe()
}
