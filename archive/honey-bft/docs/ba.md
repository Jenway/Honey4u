Algorithm BA (for party P_i)

- upon receiving input b_{input}, set est_0 := b_{input} and proceed as follows in consecutive epochs, with increasing labels r:

– multicast BVAL_r(est_r)
– bin\_values_r := {}
– upon receiving BVAL_r(b) messages from f + 1 nodes, if BVAL_r(b) has not been sent, multicast BVAL_r(b)
– upon receiving BVALr(b) messages from 2 f + 1 nodes,bin\_values_r := bin\_values_r ∪ {b}
– wait until bin\_values_r  != /0, then
    - multicast AUX_r(w) where w ∈ bin\_values_r
    - wait until at least (N − f ) AUXr messages have been received, such that the set of values carried by these messages, vals are a subset of bin_valuesr (note that bin_valuesr may continue to change as BVALr messages are received, thus this condition may be triggered upon
arrival of either an AUXr or a BVALr message)
    -  s ← Coinr.GetCoin() // See Figure 12
    - if vals = {b}, then
        - estr+1 := b
        - if (b = s%2) then output b
    - else estr+1 := s%2
- continue looping until both a value b is output in some round r,
and the value Coinr′ = b for some round r′ > r
