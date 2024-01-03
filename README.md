# What is this
This is a list of some of the utilities i wrote when working with Helium, Solana (past Helium2Solana migration), and BTC.
The code isn't beauty, won't be beauty but has to work.

## Solo lottery miner in PHP ( 😄 )
Yeah you can do it, check the btclotek.php

## Generate wallet address given mnemonic of 12 words (helium)
`./a.out "crush desk brain index action subject tackle idea trim unveil lawn live"`


## Seed2SolWallet (sod)
Provide 12 words (passphrase) and obtain Solana Wallet address, 
based on https://www.abiraja.com/blog/from-seed-phrase-to-solana-address


### Test

`g++ sod.c -lsodium -lssl -lcrypto && clear && ./a.out "crush desk brain index action subject tackle idea trim unveil lawn live"`

`Wallet58: 7EWwMxKQa5Gru7oTcS1Wi3AaEgTfA6MU3z7MaLUT6hnD`  



## Helium to Solana (hel2sol)
Provide Helium Wallet (public key) and convert to Solana Wallet address
based on https://docs.helium.com/solana/migration/exchange/

### Test
`g++ hel2sol.c -lsodium -lssl -lcrypto && clear && ./a.out  "14WigKto6TUvsf1LazykGSMs8LjEbqWZuceDucMW4g7vFwUo2Se"`

`Helium: 14WigKto6TUvsf1LazykGSMs8LjEbqWZuceDucMW4g7vFwUo2Se`

`Solana: EuMabB2GHX65CFuQJ1kTcSMNdkxTQiCeUgPK7gtkqA6`
