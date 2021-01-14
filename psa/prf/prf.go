package prf

import "fmt"
import "math/big"
import "strconv"

import "github.com/fentec-project/gofe/data"

import "golang.org/x/crypto/sha3"

func Evaluate(input string, key data.Vector, key_mod *big.Int, message_mod *big.Int) (*big.Int, error) {
    result := big.NewInt(0)
    for i := 0; i < len(key); i++ {
        integer_hash_value := Hash(input, i)
        integer_hash_value.Mod(integer_hash_value, key_mod)
        product := new(big.Int).Mul(integer_hash_value, key[i])
        result.Add(result, product.Mod(product, key_mod))
        //debug
        //fmt.Printf("integer_hash: %v, key[%v]: %v, product: %v, result: %v\n", integer_hash_value, i, key[i], product, result)
        //fmt.Printf("keymod: %v, messagemod: %v\n", key_mod, message_mod)
    }
    return_value, err := Round(result, key_mod, message_mod)
    if err != nil {
        fmt.Println("Error in Round function.")
    }
    return return_value, nil
}

func Hash(input string, pos int) (*big.Int) {
    hash_value := sha3.Sum256([]byte(strconv.Itoa(pos) + " " + input))
    integer_hash_value := big.NewInt(0)
    integer_hash_value.SetBytes(hash_value[:])
    return integer_hash_value
}

func Round(value, upper_mod, lower_mod *big.Int) (*big.Int, error) {
    if lower_mod.Cmp(upper_mod) >= 0 {
        return nil, fmt.Errorf("Illegal input to rounding function")
    }
    value.Mod(value, upper_mod)
    value.Mul(value, lower_mod)
    value.Div(value, upper_mod)
    //fmt.Printf("%v %v %v\n", value, upper_mod, lower_mod)
    
    return value, nil
}
