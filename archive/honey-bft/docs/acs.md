Figure 4: Common Subset Agreement protocol (from Ben-Oret al.)

Algorithm ACS (for party $P_i$)

Let $\{RBC_i\}_N$ refer to N instances of the reliable broadcast protocol, where $P_i$ is the sender of $RBC_i$. Let $\{BA_i\}_N$ refer to N instances of the binary byzantine agreement protocol.

- upon receiving input $v_i$, input $v_i$ to $RBC_i$
- upon delivery of $v_j$ from $RBC_j$, if input has not yet been provided to $BA_j$, then provide input 1 to $BA_j$.
- upon delivery of value 1 from at least N − f instances of BA, provide input 0 to each instance of BA that has not yet been provided input.
- once all instances of BA have completed, let C ⊂ [1..N] be the indexes of each BA that delivered 1. Wait for the output $v_j$ for each $RBC_j$ such that $j \in C$. Finally output $∪_{j∈C^vj}$.
