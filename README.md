# Privacy Preserving Smart Metering
Smart meters are capable of sending the current power consumption of an individual household to the power-supplier at regular intervals of e.g. 15 minutes. The power-supplier can use these data for load balancing in their network. However, the current power consumption of an individual household is privacy sensitive, because private information like the work schedule, or whether someone is on holiday can easily be derived from the deviation in the power consumption. To balance the client's wish for privacy and the power-suppliers wish for accurate data, one can use schemes for decentralized multi-client functional encryption (DMCFE). They allow an authorized party to compute inner products between a specified vector y and the vector consisting of the client's data. At the same time the client's data are encrypted and only the inner-product can be computed in the clear. To use DMCFE for privacy preserving smart metering, one would use y=(1,...,1), which lets the power-supplier compute the sum of the client's data.

In many (DLOG based) DMCFE schemes the sum of the client plaintexts will be in the exponent of a group element. This means, that the decryptor has to compute a discrete logarithm to obtain the result. This is not very efficient and restricts the size of the numbers that can be handled.

Private Stream Aggregation (PSA) is a weaker primitive than DMCFE that only allows computing inner-products with y=(1,...,1). Because it is a weaker primitive, PSA schemes are usually more efficient than DMCFE schemes. Furthermore, in the case of privacy preserving smart-metering, PSA schemes are sufficient.

In this project we implemet a lattice based PSA scheme and apply it to the usecase of smart metering.

## The protocol
This is a protocol of n clients (the households) and one server (the power-supplier).
### Key generation and distribution
Each client creates a diffie-hellman key-pair and a secret encryption key. The diffie-hellman public key is then exchanged with the other clients. This enables each client to compute a shared secret with all other clients. These are used to create a n out of n secret sharing of 0. Each client uses their share to encrypt (in a one time pad way) their secret encryption key and send it to the server. The server is able to decrypt the sum of the keys.

### Encryption
At every time-step (e.g. every 15 minutes) the clients encrypt their current power consumption with their secret encryption key and send the ciphertext to the aggregator

### Decryption
The aggregator can use the key obtained by the clients in the first phase to compute the sum of the client's plaintexts.

## The demo
The demo uses the PSA scheme to simulate the smart meter use case. Additionally it executes the DMCFE scheme for the same scenario to enable a comparison between the scheems. The number of clients, the number of time-steps (labels) and the maximum power-consumption per client can be set as constants in the source code.

### How to run the demo
Download the repository and run "go run smartmeter.go" in the folder "smartmeter"
