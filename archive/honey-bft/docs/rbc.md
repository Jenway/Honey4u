### Algorithm 2: Reliable Broadcast

**For party $P_i$, with sender $P_{Sender}$**

*   **Upon input $(v)$ (if $P_i = P_{Sender}$):**
    1.  Let $\{s_j\}_{j \in [1..N]}$ be the blocks of an $(N-2f, N)$-erasure coding scheme applied to $v$.
    2.  Let $h$ be a Merkle tree root computed over $\{s_j\}$.
    3.  Send `VAL(h, b_j, s_j)` to each party $P_j$, where $b_j$ is the $j$-th Merkle tree branch.

*   **Upon receiving `VAL(h, b_i, s_i)` from $P_{Sender}$:**
    *   Multicast `ECHO(h, b_i, s_i)`.

*   **Upon receiving `ECHO(h, b_j, s_j)` from party $P_j$:**
    *   Check that $b_j$ is a valid Merkle branch for root $h$ and leaf $s_j$, and otherwise discard.

*   **Upon receiving valid `ECHO(h, \cdot, \cdot)` messages from $N-f$ distinct parties:**
    1.  Interpolate $\{s'_j\}$ from any $N-2f$ leaves received.
    2.  Recompute Merkle root $h'$ and if $h' \neq h$ then abort.
    3.  If `READY(h)` has not yet been sent, multicast `READY(h)`.

*   **Upon receiving $f+1$ matching `READY(h)` messages:**
    *   If `READY(h)` has not yet been sent, multicast `READY(h)`.

*   **Upon receiving $2f+1$ matching `READY(h)` messages:**
    *   Wait for $N-2f$ `ECHO` messages, then decode $v$.
