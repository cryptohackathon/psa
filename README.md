# Privacy Preserving Smart Metering
Smart meters are capable of sending the current power consumption of an individual household to the power-supplier at regular intervals of e.g. 15 minutes. The power-supplier can use these data for load balancing in their network. However, the current power consumption of an individual household is privacy sensitive, because private information like the work schedule, or whether someone is on holiday can easily be derived from the deviation in the power consumption. To balance the client's wish for privacy and the power-suppliers wish for accurate data, one can use schemes for decentralized multi-client functional encryption (DMCFE). They allow an authorized party to compute inner products between a specified vector y and the vector consisting of the client's data. At the same time the client's data are encrypted and only the inner-product can be computed in the clear. To use DMCFE for privacy preserving smart metering, one would use y=(1,...,1), which lets the power-supplier compute the sum of the client's data.

In many (DLOG based) DMCFE schemes the sum of the client plaintexts will be in the exponent of a group element. This means, that the decryptor has to compute a discrete logarithm to obtain the result. This is not very efficient and restricts the size of the numbers that can be handled.

Private Stream Aggregation (PSA) is a weaker primitive than DMCFE that only allows computing inner-products with y=(1,...,1). Because it is a weaker primitive, PSA schemes are usually more efficient than DMCFE schemes. Furthermore, in the case of privacy preserving smart-metering, PSA schemes are sufficient.

In this project we implemet a lattice based PSA scheme and apply it to the usecase of smart metering.

## The protocol

## How to run the demo
