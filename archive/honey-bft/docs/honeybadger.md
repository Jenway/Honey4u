### Algorithm : HoneyBadgerBFT (for node Pi)

Let $B = Ω(λ N2 log N)$ be the batch size parameter.

Let $P_K$ be the public key received from TPKE.Setup (executed by a dealer), and let $S_{Ki}$ be the secret key for $P_i$.

Let buf := [ ] be a FIFO queue of input transactions.
Proceed in consecutive epochs numbered r:
// Step 1: Random selection and encryption
• let proposed be a random selection of bB/Nc transactions from
the first B elements of buf
• encrypt x := TPKE.Enc(PK, proposed)
// Step 2: Agreement on ciphertexts
• pass x as input to ACS[r] //see Figure 4
• receive {v j} j∈S, where S ⊂ [1..N], from ACS[r]
// Step 3: Decryption
• for each j ∈ S:
let e j := TPKE.DecShare(SKi, v j)
multicast DEC(r, j, i, e j)
wait to receive at least f + 1 messages of the form
DEC(r, j, k, e j,k)
decode y j := TPKE.Dec(PK, {(k, e j,k)})
• let blockr := sorted(∪ j∈S{y j}), such that blockr is sorted in a
canonical order (e.g., lexicographically)
• set buf := buf − blockr
