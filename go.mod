module github.com/polynetwork/ripple-voter

go 1.17

require (
	github.com/boltdb/bolt v1.3.1
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/polynetwork/poly v1.8.4-0.20220310043944-b07dfc3df5f8
	github.com/polynetwork/poly-go-sdk v0.0.0-20220126075452-e5c053a49c0a
	github.com/polynetwork/ripple-sdk v1.0.0
	github.com/rubblelabs/ripple v0.0.0-20220222071018-38c1a8b14c18
)

require (
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/Workiva/go-datastructures v1.0.52 // indirect
	github.com/bits-and-blooms/bitset v1.2.1 // indirect
	github.com/btcsuite/btcd v0.21.0-beta // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/ethereum/go-ethereum v1.9.25 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/snappy v0.0.3-0.20201103224600-674baa8c7fc3 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/itchyny/base58-go v0.1.0 // indirect
	github.com/ontio/go-bip32 v0.0.0-20190520025953-d3cea6894a2b // indirect
	github.com/ontio/ontology-crypto v1.0.9 // indirect
	github.com/ontio/ontology-eventbus v0.9.1 // indirect
	github.com/orcaman/concurrent-map v0.0.0-20190826125027-8c72a8bb44f6 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20200815110645-5c35d600f0ca // indirect
	github.com/tyler-smith/go-bip39 v1.0.2 // indirect
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871 // indirect
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b // indirect
	golang.org/x/term v0.0.0-20201126162022-7de9c90e9dd1 // indirect
)

replace (
	github.com/polynetwork/poly v1.8.4-0.20220310043944-b07dfc3df5f8 => github.com/siovanus/poly v1.7.3-0.20220311083551-df1ce0ad150c
	github.com/polynetwork/poly-go-sdk v0.0.0-20220126075452-e5c053a49c0a => github.com/siovanus/poly-go-sdk v0.0.0-20220314125958-f7122a8fecf2
	github.com/polynetwork/ripple-sdk v1.0.0 => github.com/siovanus/ripple-sdk v1.0.1-0.20220311082414-84e86a29df1a
	github.com/rubblelabs/ripple v0.0.0-20220222071018-38c1a8b14c18 => github.com/siovanus/ripple v0.0.0-20220311080636-cbff6a9e07ce
	github.com/tendermint/tm-db/064 => github.com/tendermint/tm-db v0.6.4
)
