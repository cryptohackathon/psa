package psa

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
	//"strconv"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	
	"psa/psa/prf"
)

type PSAClient struct {
    Idx int
    ClientSecKey *big.Int
    ClientPubKey *bn256.G1
    Share data.Vector
    ClientEncKey data.Vector
}

var message_mod *big.Int = new(big.Int).Exp(big.NewInt(2), big.NewInt(64) ,nil)
var key_mod *big.Int = new(big.Int).Exp(big.NewInt(2), big.NewInt(84) ,nil)
const dimension int = 2

func NewPSAClient(idx int) (*PSAClient, error) {
	dh_sampler := sample.NewUniform(bn256.Order)
	prf_sampler := sample.NewUniform(key_mod)
	
	//create encryption key
	ek, err := data.NewRandomVector(dimension, prf_sampler)
	if err != nil {
		return nil, fmt.Errorf("could not generate encryption key")
	}
	
	//create diffie-hellman key pair
	dh_sk, err := dh_sampler.Sample()
	if err != nil {
		return nil, fmt.Errorf("could not generate dh secret key")
	}
	dh_pk := new(bn256.G1).ScalarBaseMult(dh_sk)

	return &PSAClient{
		Idx:          idx,
		ClientSecKey: dh_sk,
		ClientPubKey: dh_pk,
		ClientEncKey: ek,
	}, nil
}

func (c *PSAClient) SetShare(pubKeys []*bn256.G1) error {
    c.Share = data.NewConstantVector(dimension, big.NewInt(0))
	var add data.Vector
	var err error
	for i := 0; i < len(pubKeys); i++ {
		if i == c.Idx {
			continue
		}
		sharedG1 := new(bn256.G1).ScalarMult(pubKeys[i], c.ClientSecKey)
		sharedKey := sha3.Sum256([]byte(sharedG1.String()))

		add, err = data.NewRandomDetVector(dimension, key_mod, &sharedKey)
		if err != nil {
			return err
		}

		if i < c.Idx {
			c.Share = c.Share.Add(add)
			if err != nil {
				return err
			}
		} else {
			c.Share = c.Share.Sub(add)
			if err != nil {
				return err
			}
		}
		c.Share = c.Share.Mod(key_mod)
	}
    //fmt.Println(c.Share)
	return nil
}

func (c *PSAClient) Encrypt(x *big.Int, label string, num_users int) (*big.Int, error) {
    prf_value, err := prf.Evaluate(label, c.ClientEncKey, key_mod, message_mod)
    //fmt.Printf("prf_value[%v]: %v\n", c.Idx, prf_value)
    if err != nil {
        fmt.Println(err)
        return nil, err
    }
    
    x_new, err := preprocessing(x, num_users)
    if err != nil {
        return nil, err
    }
    
    ciphertext := new(big.Int).Add(prf_value, x_new)
    ciphertext.Mod(ciphertext, message_mod)
    return ciphertext, nil
}

//This method must only be use for y=(1,...,1), because otherwise the security proof does not app
//The keys are encrypted in a one time pad manner
func (c *PSAClient) DeriveKeyShare(y data.Vector) (data.Vector, error) {
    //check if y is (1,...,1)
    for i :=0 ; i < len(y); i++ {
        if y[i].Cmp(big.NewInt(1)) != 0 {
            fmt.Println("y != (1,...,1). There is no security proof for this case.")
            fmt.Println("If you use more than one vector y, the scheme is not secure.")
            return nil, fmt.Errorf("y != (1,...,1)")
        }
    }
    
    if c.Share == nil {
        fmt.Println("Share == nil")
        return nil, fmt.Errorf("Share == nil")
    }
    
    result := data.NewConstantVector(dimension, big.NewInt(0))
    result = c.Share.Add(c.ClientEncKey)
    result = result.Mod(key_mod)
     
    return result, nil
}

//I dropped y and bound as parameters.
func PSADecrypt(ciphers []*big.Int, keyShares []data.Vector, label string, num_clients int) (*big.Int, error) {
    
    if len(ciphers) != len (keyShares) {
        return nil, fmt.Errorf("num ciphertexts = %v != %v = num keyShares", len(ciphers), len(keyShares))
    }

    sum := big.NewInt(0)
    for i := 0; i < len(ciphers); i++ {
        sum.Add(sum, ciphers[i])
    }
    
    //combine shares to get the prf key.
    key := data.NewConstantVector(dimension, big.NewInt(0))
    for i := 0; i < len(keyShares); i++ {
        key = key.Add(keyShares[i])
    }
    key = key.Mod(key_mod)
    prf_value, err := prf.Evaluate(label, key, key_mod, message_mod)
    if err != nil {
        return nil, err
    }
    
    //fmt.Printf("Agg-prf-value: %v\n", prf_value)
    sum.Mod(sum, message_mod)
    sum.Sub(sum, prf_value)
    if sum.Cmp(big.NewInt(0)) <= 0 {
        sum.Add(sum, message_mod)
    }
    
    
    sum, err = postprocessing(sum, num_clients)
    if err != nil {
        return nil, err
    }
    sum.Mod(sum, message_mod)
    
    return sum, nil
}

//This function must be called to before the actual encryption, because the PRF is only *almost* key-homomorphic
//x is the plaintext. The return value is what will then be input to the actual encryption
func preprocessing(x *big.Int, n int) (*big.Int, error) {
    result := big.NewInt(0)
    result.Mul(x, big.NewInt(int64(n)))
    result.Add(result, big.NewInt(1))
    
    if result.Cmp(message_mod) >= 0 {
        return nil, fmt.Errorf("Result = %v >= %v = message_mod", result, message_mod)
    }
    return result, nil
}

//This function must be called after decryption, to accomodate for the only *almost* key-homomorphism
//x is the output of the actual decryption. The return value is the sum of the plaintexts
func postprocessing(x *big.Int, n int) (*big.Int, error) {
    result := big.NewInt(0)
    //fmt.Printf("x: %v, result: %v\n", x, result)
    //round x up to closest multiple of n
    remainder := big.NewInt(0)
    remainder.Mod(x, big.NewInt(int64(n)))
    if remainder.Cmp(big.NewInt(0)) == 0 {
        result = x
        //fmt.Println("remainder zero")
        //fmt.Printf("x: %v, result: %v\n", x, result)
    } else {
        result.Add(x, big.NewInt(int64(n)))
        result.Sub(result, remainder)
        //fmt.Println("remainder non-zero")
        //fmt.Printf("x: %v, result: %v\n", x, result)
    }
    
    result.Sub(result, big.NewInt(int64(n)))
    //fmt.Printf("x: %v, result: %v\n", x, result)
    result.Div(result, big.NewInt(int64(n)))
    //fmt.Printf("x: %v, result: %v\n", x, result)
    return result, nil
}

func main() {
    fmt.Println("m-mod: %v", message_mod)
    fmt.Println("k-mod: %v", key_mod)
    
    //create psaclient and print parameters
    //client, err := NewPSAClient(0)
    //if err != nil {fmt.Println("Error while creating client")}
    
    //temp_vec, _ := data.NewRandomVector(5, sample.NewUniform(big.NewInt(1000)))
    //client.DeriveKeyShare(temp_vec)
    
    //fmt.Println("Client: %+v", client)
    
    //temp_value, _ := prf.Round(big.NewInt(129),big.NewInt(128),big.NewInt(32))
    //fmt.Println("%v", temp_value)
    //key_vector, _ := data.NewRandomVector(5, sample.NewUniform(big.NewInt(32)))
    //prf_value, _ := prf.Evaluate("hello", key_vector, key_mod, message_mod)
    //fmt.Println(prf_value)
    
    test_num_clients := 100
    var clients []*PSAClient
    for i := 0; i < test_num_clients; i++ {
        c, _ := NewPSAClient(i)
        clients = append(clients, c)
    }
    var pub_keys []*bn256.G1
    for i := 0; i < test_num_clients; i++ {
       pub_keys = append(pub_keys, clients[i].ClientPubKey)
    }
    for i := 0; i < test_num_clients/2; i++ {
        clients[i].SetShare(pub_keys)
    }
    
    for i := test_num_clients/2; i < test_num_clients; i++ {
        clients[i].SetShare(pub_keys)
    }
    
    //Test if the Shares of the clients sum to zero
    temp_sum := data.NewConstantVector(dimension, big.NewInt(0))
    for i := 0; i < test_num_clients; i++ {
        temp_sum = temp_sum.Add(clients[i].Share)
        //fmt.Printf("Share[%v]: %v\n", i, clients[i].Share)
    }
    fmt.Printf("Mod-Sum of shares: %v\n", temp_sum.Mod(key_mod))
    
    //Test if keyShares sum to sum of keys.
    var key_shares []data.Vector
    func_key := data.NewConstantVector(dimension, big.NewInt(0))
    sum_keys := data.NewConstantVector(dimension, big.NewInt(0))
    y := data.NewConstantVector(test_num_clients, big.NewInt(1))
    for i := 0; i < test_num_clients; i++ {
        user_key_share, _ := clients[i].DeriveKeyShare(y)
        key_shares = append(key_shares, user_key_share)
        func_key = func_key.Add(key_shares[i])
        //fmt.Printf("key_share[%v]: %v\n", i, key_shares[i])
        sum_keys = sum_keys.Add(clients[i].ClientEncKey)
    }
    func_key = func_key.Mod(key_mod)
    sum_keys = sum_keys.Mod(key_mod)
    fmt.Printf("func_key: %v, sum_keys: %v\n", func_key, sum_keys)
    
    //Look at the keys
    for i := 0; i < test_num_clients; i++ {
        //fmt.Printf("Key[%v]: %v\n", i, clients[i].ClientEncKey)
    }
    
    //Look at the encrypted messages
    plaintexts, _ := data.NewRandomVector(test_num_clients, sample.NewUniform(big.NewInt(200)))
    //plaintexts := data.NewConstantVector(test_num_clients, big.NewInt(1))
    actual_sum := big.NewInt(0)
    var ciphertexts []*big.Int
    for i := 0; i < test_num_clients; i++ {
        cipher, _ := clients[i].Encrypt(plaintexts[i], "0001", test_num_clients)
        ciphertexts = append(ciphertexts, cipher)
        //fmt.Printf("Ciphertext[%v]: %v\n", i, ciphertexts[i])
        actual_sum.Add(actual_sum, plaintexts[i])
    }
    for i := 0; i < test_num_clients; i++ {
        //fmt.Printf("Plaintext[%v]: %v\n", i, plaintexts[i])
    }
    
    //Try to decrypt
    decryption, err := PSADecrypt(ciphertexts, key_shares, "0001", test_num_clients)
    if err != nil {
        fmt.Println(err)
    } else {
        fmt.Printf("decryption: %v, actual sum: %v\n", decryption, actual_sum)
    }
    
    
    
    
    
    
    
    
    
    
    
    
}
