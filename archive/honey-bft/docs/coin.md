### Algorithm $Coin_sid$ for party $p_i$

sid is assumed to be a unique nonce that serves as "name" of this common coin

- (Trusted Setup Phase): A trusted dealer runs $pk,{sk_i} <- ThresholdSetup}$ to generate a common public key, as well as secret key shares {sk_i}, one for each party(secrect key sk+i is distributed to party p_i).
    - Note that a single setup can be used to support a family of Coinx indexed by arbitrary sid strings


- On input $GetCoin$, multicast $ThresholdSign_pk(sk_i,sid)$
- Upon Receiving at least $f+1$ shares, attempt to combine them into a signature:

$$
SIG <- ThresholdCombine_pk({j,s_j})
if ThresholdVerify_pk(sid) then deliver sig
$$
