#import "lib.typ": sdu-thesis, thesis-table
#import "utils.typ": algox

#show: sdu-thesis.with(
  title: "面向异步共识协议的广播数据跨轮次复用机制设计与实现",
  author: "刘振伟",
  school_id: "202200130086",
  school: "计算机科学与技术学院",
  major: "计算机科学与技术",
  grade: "2022级",
  supervisor: "高英梓",
  date: "2026年5月7日",

  // 中文摘要一般 300 - 800 个汉字
  abstract_zh: [
    异步拜占庭容错（BFT）共识协议能够在极端的网络延迟下保证系统活性。当前主流基于异步公共子集（ACS）的协议（如 Dumbo 系列）普遍采用广播与共识严格串行的两阶段架构。然而，这种串行设计导致每轮共识中“诚实但迟到”的广播数据被直接丢弃，造成了网络带宽浪费与系统吞吐量损失。

    为了解决这一带宽浪费问题，本文提出了一种面向串行 ACS 协议的跨轮次的广播数据复用机制。该机制不需要修改原有 ACS 的内部决定语义。具体而言，节点在每轮结束后会开启一个有限时长的截留窗口，将迟到但已生成可用性证明的广播数据存入本地复用池；在后续轮次中，这些历史数据会被编码为轻量引用，作为新提案的一部分重新注入共识系统。同时，为了应对引用数据在本地未命中的情况，本文设计了独立的异步回取（Fetch）路径来保障协议活性。

    本课题基于 Rust 语言开发了原型系统，并集成了 Dumbo 与 FIN 两种主流的 ACS 后端。本地多进程仿真实验结果表明，在典型的高负载场景下，开启复用机制能将端到端吞吐量稳定提升 10% 至 20%；在引入慢节点与静默节点的故障测试中，该机制也表现出了良好的鲁棒性。总之，本文方案以较小的工程代价回收了被浪费的广播带宽，为串行异步共识系统的性能优化提供了一种易落地的参考。
  ],
  keywords_zh: ("异步拜占庭容错", "异步公共子集", "HoneyBadger", "Dumbo", "跨轮次复用"),

  // 英文摘要约 200 - 600 个实词
  abstract_en: [
    The Asynchronous Byzantine Fault Tolerance (BFT) consensus protocol ensures system liveness even under extreme network latency. Current mainstream protocols based on Asynchronous Common Subset (ACS), such as the Dumbo series, generally adopt a two-phase architecture in which broadcasting and consensus are strictly serialized. However, this serial design causes “honest-but-late” broadcast data to be discarded in each consensus round, resulting in wasted network bandwidth and reduced system throughput.

    To address this bandwidth waste, this paper proposes a cross-round broadcast data reuse mechanism for serial ACS protocols. This mechanism does not require any modification to the original ACS’s internal decision semantics. Specifically, after each round concludes, nodes open a time-limited retention window to store delayed broadcast data—for which proofs of availability have already been generated—into a local reuse pool. In subsequent rounds, this historical data is encoded as lightweight references and reintroduced into the consensus system as part of new proposals. Additionally, to address cases where referenced data is not cached locally, this paper designs an independent asynchronous fetch path to ensure protocol liveness.

    We developed a prototype system for this research using the Rust programming language and integrated two mainstream ACS backends: Dumbo and FIN. Local multi-process simulation results show that, under typical high-load scenarios, enabling the reuse mechanism can consistently increase end-to-end throughput by 10% to 20%. In fault tests involving slow and silent nodes, the mechanism also demonstrated good robustness. In summary, the proposed solution recovers wasted broadcast bandwidth at a relatively low engineering cost, providing a practical reference for performance optimization in serial asynchronous consensus systems.

  ],
  keywords_en: ("asynchronous BFT", "ACS", "HoneyBadger", "Dumbo", "cross-round reuse"),

  bibliography_file: "refer.bib",

  acknowledgements: [
    感谢我的导师高英梓老师。高老师在本课题的内容与方向、毕设各阶段工作规划、原型系统与实验设计等方面给予我很多非常有益的建议和指导；本课题“回收迟到诚实广播数据并跨轮次复用”的思路也同样来自于高老师。

    本课题原型系统中的 Dumbo ACS 协议黑盒来自于开源社区代码，FIN-style ACS 协议黑盒的实现则参考了 JUMBO 论文的开源实现。

    祝愿所有帮助过我的人幸福快乐。

    本课题的设计与撰写过程中，在思路拓展、逻辑梳理、辅助代码编写以及文本语法润色等方面，使用了生成式大语言模型辅助
  ],

  appendix: [
  ],
)

= 绪论
// 约 2000 字

== 研究背景与问题

异步拜占庭容错（Byzantine Fault Tolerance, BFT）共识协议旨在容忍至多 $f$ 个节点发生任意故障的前提下，在网络消息延迟不存在上界的纯异步环境中，使所有诚实节点仍能就同一批交易或区块的顺序达成一致。与依赖同步或部分同步假设的经典协议（如 PBFT @castroPracticalByzantineFault2002）不同，异步 BFT 不依赖超时机制来判断节点失效，因而在网络条件剧烈波动、极易发生网络分区的广域网环境中具备天然的活性（Liveness）优势，更适合构建高可用的分布式系统。

基于异步公共子集（Asynchronous Common Subset, ACS）实现的异步 BFT 协议因其结构简洁、模块化程度高而受到广泛关注，代表性工作包括 HoneyBadger @millerHoneyBadgerBFT2016 与 Dumbo @guoDumboFasterAsynchronous2020 系列协议。经典的 ACS 协议通常划分为广播与共识两个严格串行的阶段：广播阶段负责使各节点的提案广泛可用，共识阶段则在此基础上从至少 $N-f$ 个提案中选出公共子集作为本轮输出。

然而，严格串行的结构带来了一个网络带宽浪费问题：一旦节点成功收集到至少 $N-f$ 个可用性证明，即可结束本轮广播阶段的等待并推进共识。此时，其余诚实节点（至多 $f$ 个）的广播进程仍在进行中。即使这些提案最终完成了网络传输并取得了可用性证明，也会因落后于当前的共识进度而被直接丢弃。对于这些“诚实但迟到”的广播负载，底层网络已经为其支付了全额的带宽成本，但共识层却未能对这些成果加以利用。其宏观结果表现为系统有效吞吐量的下降和广播冗余的增加；在系统负载较高或节点间计算与网络性能存在明显差异的部署环境中，这种资源浪费尤为突出。

== 研究意义

近年来，为解决上述串行阶段带来的性能瓶颈，学术界提出了多种完全并行的异步共识架构（如基于 DAG 的 Narwhal and Tusk @danezisNarwhalTuskDAGbased2022 等）。然而，这类方法通常需要对协议进行颠覆性重构，大幅增加状态维护的复杂性。

相比之下，在经典串行 ACS 架构基础上引入广播数据跨轮次复用机制，能够在不改变现有协议骨架与内部决定语义的前提下，有效回收被丢弃的迟到广播成果。这一思路将外层调度优化与底层共识引擎解耦，降低了工程实现难度，便于已有的异步 BFT 系统进行增量式平滑迁移，具有直接且迫切的工程参考价值。同时，随着区块链、联盟链以及分布式数据库等基础设施对高吞吐、低浪费特性的持续追求，此类轻量级、可落地的协议层带宽优化手段有其明显的应用意义。

== 研究目标与主要贡献

本文以串行 ACS 协议中的历史广播数据浪费问题为切入点，提出并实现了一种面向异步 BFT 的跨轮次广播复用方法，通过对“诚实但迟到”的数据进行缓存复用来降低带宽损耗并提升整体吞吐量。本文围绕该机制的协议设计、系统实现以及本地仿真评估展开工作，主要贡献包括：

1. *机制设计与安全性论证*：提出了一种面向串行 ACS 协议的跨轮次复用机制。将复用对象严格限定为“已取得可用性证明、但因时序落后未被采纳”的历史提案，通过引入生命周期截留窗口，确保复用机制作为宿主层逻辑不侵入 ACS 的决定语义，并在理论上维护了原协议的安全性与活性边界。
2. *原型系统实现*：围绕统一提案格式编码、缓存生命周期管理（Grace Window）、引用消费去重以及基于异步回取（Fetch）的缺失数据恢复等关键环节，对协议栈进行了端到端的设计与改造，并基于 Rust 语言完成了融合多语言 ACS 后端的原型系统开发。
3. *多维度实验评估*：在本地仿真环境中，针对高负载、截留敏感性及受控网络扰动等多种场景进行了对比实验。结果表明，在典型高负载设置下，跨轮次复用能够将系统端到端吞吐量稳定提升 10% 至 20%。

== 论文组织结构

本文后续章节安排如下：
第二章回顾相关研究，梳理异步 BFT 协议的发展脉络和已有性能优化的学术尝试；
第三章详细阐述跨轮次复用机制的系统模型、前置条件、设计细节与安全性分析；
第四章介绍多层级解耦的原型系统实现与仿真实验设计，并对实验结果进行深度量化分析；
第五章总结全文并讨论未来的研究方向。

= 背景与相关工作

// 约 2000 字

共识协议，即分布式系统中多个节点就某个数据或状态达成一致意见的规则与机制 @LiuYiZhongQuKuaiLianGongShiJiZhiYanJiuZongShu2019，其中 BFT 共识协议保证了在有节点作恶的情况下仍然保证协议正确。而从时间假设来说，又可以分为：同步、弱同步与异步共识协议，异步共识协议不需要通过超时机制来判断对方是否失效，从而能够在网络条件极不稳定时仍保持活性保证。

换言之，异步 BFT 共识协议在至多 $f$ 个节点任意作恶、网络消息延迟无上界的条件下，仍能确保诚实节点对同一批交易或区块顺序达成一致。

在纯异步网络模型下，由于无法使用超时机制来判断节点是否发生崩溃或拜占庭故障，共识协议的设计面临着极其严苛的理论限制（如 FLP 不可能定理）。传统的解决思路是引入随机化操作，允许系统以概率为 1 终止。

== ACS 与异步 BFT

自 HoneyBadgerBFT @millerHoneyBadgerBFT2016 首次证明异步 BFT 在实际广域网中的可行性以来，基于 ACS 范式的架构便成为了该领域的主流。ACS 允许 $N$ 个节点各自提出输入值，并确保所有诚实节点最终输出完全相同的、包含至少 $N-f$ 个提案的公共子集。@millerHoneyBadgerBFT2016 指出：通过结合门限加密技术，ACS 可被直接转化为异步原子广播（Asynchronous Atomic Broadcast, AAB），进而构建完整的共识账本。

ACS 的早期理论来源可以追溯到 Ben-Or、Kelmer 与 Rabin 对异步安全计算和公共子集问题的研究 @ben-orAsynchronousSecureComputations1994。@ben-orAsynchronousSecureComputations1994 中提出的 ACS 范式（其核心结构由 $N$ 个可靠广播（RBC）实例与 $N$ 个异步二元拜占庭共识（ABA）实例组成）被许多文献称之 BKR94 范式。HoneyBadgerBFT 便是该范式的典型代表。

另一个比较主要的范式被称之为 CKPS01 @cachinSecureEfficientAsynchronous2001 范式，由 Cachin 等人于 2001 年提出，该范式利用多值拜占庭共识（MVBA）代替了复杂的 $N$ 个 ABA 实例。正如 @millerHoneyBadgerBFT2016 中所指出的：在早期实现中，CKPS01 范式要求将完整的提案负载直接输入给 MVBA，导致极高的通信复杂度。

Dumbo 协议 @guoDumboFasterAsynchronous2020 对 CKPS01 范式做出了关键突破。Dumbo 结合了两种范式的优点，通过引入可证明可靠广播（Provable Reliable Broadcast, PRBC），在广播阶段完成大负载的传输与可用性证明，随后仅将轻量级的证明（Proof）作为向量输入给后端的 MVBA。这种设计将 ACS 的一致性阶段从“对每个提案进行 $N$ 次二值决定”转化为“围绕一个已验证的候选向量达成一次决定”，从而显著降低了延迟并提升了吞吐量。

Dumbo2 ACS 结构中的 MVBA 是作为一个可插拔的“黑盒”组件存在的，因此可以任意替换，有诸多研究（如 Dumbo-MVBA @luDumboMVBAOptimalMultivalued2020、sDumbo @guoSpeedingDumboPushing2022、以及基于无签名设置的 FIN @duanFINPracticalSignaturefree2023）聚焦于优化 MVBA 内部的密码学开销或通信轮数。由于本文的跨轮次复用机制作用于 ACS 的输入边界而非内部逻辑，因此在后续设计中，上述 MVBA 变体均可视作透明的底层黑盒。此外，PACE @zhangPACEFullyParallelizable2022 等工作通过引入可重提的一致性框架（RABA）对 BKR94 结构进行了改良，这些工作在广义上均属于经典串行 ACS 的演进。

基于有向无环图（DAG）的异步 BFT 协议绕开了 ACS，如 DAG-rider @keidarAllYouNeed2021；2022 年的 Narwhal and Tusk @danezisNarwhalTuskDAGbased2022 通过将 Mempool 协议和共识协议进行并行解耦，获得了很好的性能。2025 年的 Mysticeti @babelMysticetiReachingLatency2025 则将 DAG 路径的延迟推至消息复杂度下界。基于 DAG 的协议实现相比基于 ACS 的协议在实现上会更复杂。

== 并行化架构与带宽利用

经典的 ACS 结构（无论是 HoneyBadger 还是 Dumbo）严格遵守“广播完毕后触发共识”的串行两阶段执行逻辑。正如 DispersedLedger @yangDispersedLedgerHighthroughputByzantine2022 论文中所指出的，这种严格串行会造成系统资源的阶段性闲置：广播阶段主要受限于带宽资源，而共识阶段（尤其是涉及复杂密码学运算的 ABA 或 MVBA）主要受限于 CPU 与时间资源。

为了打破这种串行瓶颈，学术界提出了多种并行化方案。

第一种思路是弱化广播原语，在广播阶段不强制要求数据全网可达，而是在共识决定输出后，增加一个异步的回取（Retrieval）阶段来下载缺失数据。DispersedLedger 和 sDumbo @guoSpeedingDumboPushing2022 都使用了类似的优化方法。

第二种思路是将广播与共识完全解耦，通过流水线（Pipelining）设计同时推进多轮共识。Dumbo-NG @gaoDumboNGFastAsynchronous2022 通过维护多轮次的水位线（Watermark）来实现这一目标。JUMBO @chengMathsfJUMBOJUMBOFully2025 则在 Dumbo-NG 框架的基础上，通过签名聚合技术将通信复杂度从 $O(n^3)$ 降至 $O(n^2)$，
为此类并行化方案的后续扩展提供了重要的工程参考

第三种方案是放弃 ACS 结构，使用新的共识范式。以 Narwhal and Tusk @danezisNarwhalTuskDAGbased2022 为代表的 DAG 共识协议，通过在底层内存池节点间维护图结构的偏序关系，实现了广播与共识的完全并发。Bolt-Dumbo Transformer @luBoltdumboTransformerAsynchronous2022 则在 DAG 与传统 ACS 之间搭建了通用适配框架，实现了乐观路径与异步回退的灵活切换。

然而，这些并行化方案往往以增加协议状态机复杂度和元数据维护开销为代价。本文的研究不寻求对共识内核进行并发重构，而是专注于对传统且部署广泛的串行 ACS 结构进行局部优化。

== 迟到广播与带宽浪费问题

在严格串行的 ACS 架构中，系统推进必须满足活性要求：只要节点收集到 $N-f$ 个合法的广播证明，就必须立即进入共识阶段，而不能无限期等待所有 $N$ 个提案完成（以防止拜占庭节点因拒不发包而导致系统停滞）。这一机制必然导致一个副作用：本轮共识中，剩下至多 $f$ 个诚实节点的广播提案即使最终到达，也会因时序落后而被系统丢弃，造成严重的带宽浪费。

并行的 ACS 协议则不会有这种浪费问题。

DispersedLedger @yangDispersedLedgerHighthroughputByzantine2022 对此问题有过深入探讨。在基于 BKR94 范式的 HoneyBadger 中，节点一旦收到 $N-f$ 个 RBC 完成消息，便会向本地所有的 $N$ 个 ABA 实例投出初始票。在网络同质性较好的情况下，其余 $f$ 个 RBC 仍有较大概率在 ABA 结束前完成全局终止。然而，在网络波动较大的情况下，浪费依然严重。为此，@yangDispersedLedgerHighthroughputByzantine2022 提出了 `internodelinking` 机制：在消息头中维护向量与水位线（本质上是提取并维护一种轻量级的偏序信息），使后续节点能够据此计算出历史消息的合法性并将其链入主账本。

需要指出的是，`internodelinking` 机制深度修改了 BKR94 范式内部 RBC 与 ABA 之间的交互图谱，其耦合度极高。对于基于 CKPS01 范式（即 PRBC + MVBA）的 Dumbo 风格协议而言，这种深度的内部结构修改难以直接迁移。针对这一痛点，本文提出一种非侵入式的跨轮次复用机制，旨在无需引入复杂偏序状态机、不改动 MVBA 内部语义的前提下，解决串行 ACS 中的广播浪费问题。

= 跨轮次复用机制的设计

// 约 3000 字

== 问题建模与系统假设

本文采用与 HoneyBadgerBFT @millerHoneyBadgerBFT2016 和 Dumbo @guoDumboFasterAsynchronous2020 相同的系统模型，具体假设如下：

- *节点与网络*：设系统中有 $n$ 个节点集合 $P = {P_1, P_2, ..., P_n}$。节点的身份与公钥信息公开可信。网络为纯异步认证点对点网络，任意两个节点间存在可靠的认证信道；攻击者可以任意延迟、重排或丢弃消息，但诚实节点之间发送的消息若经历无限时间等待，最终必然送达。
- *故障模型*：系统中最多存在 $f$ 个静态的拜占庭故障节点（满足 $n >= 3f + 1$）。攻击者在协议开始前可完全控制这 $f$ 个节点，获取其内部状态，并能在协议执行期间使其发生任意偏离协议的恶意行为。

在该模型下，我们旨在构造一个 $n$ 节点参与的异步原子广播（Asynchronous Atomic Broadcast）协议。协议按连续的轮次（Epoch）推进，每轮结束后系统输出一批新的交易并追加到全局已提交日志中。该协议需以压倒性概率满足以下性质：

- *一致性（Agreement）*：如果某个诚实节点输出交易序列 $v$，那么所有诚实节点最终都会输出 $v$；
- *全序性（Total Order）*：如果两个诚实节点分别输出历史日志序列 $chevron.l v_0, v_1, ..., v_j chevron.r$ 和 $chevron.l v'_0, v'_1, ..., v'_{j'} chevron.r$，那么对于所有 $i <= min(j, j')$，必定满足 $v_i = v'_i$；
- *抗审查性（Censorship Resilience）*：如果某笔交易被 $n - f$ 个诚实节点作为输入提交，那么最终每个诚实节点都会在日志中输出该交易。

我们采用与 HoneyBadgerBFT @millerHoneyBadgerBFT2016 类似的构造思路，即先实现异步公共子集（ACS），再结合门限加密将 ACS 转化为原子广播。有效的 ACS 协议必须满足以下性质：

- *一致性（Agreement）*：若某个诚实节点输出集合 $V$，则所有诚实节点都输出 $V$；
- *有效性（Validity）*：若某个诚实节点输出集合 $V$，则 $|V| >= n - f$，且 $V$ 至少包含 $n - 2f$ 个诚实节点的输入；
- *完备性（Termination）*：如果有 $n - f$ 个诚实节点提供了输入，则所有诚实节点最终都能输出结果。

除以上经典定义外，本文进一步要求所采用的 ACS 协议必须保证：

1. 满足严格的两阶段串行结构：广播阶段与共识阶段必须严格先后执行。
2. 具有可用性证明：广播阶段中的每个实例必须产出可独立验证的完成证明（Proof of Availability），使任意节点能据此判断数据是否安全可用。
3. 支持异步事件暴露：ACS 协议需能够向外层宿主环境异步抛出内部的关键状态事件（如局部广播完成、全局共识决定输出等），具体接口将在后文详细描述。

Dumbo2 协议完整满足上述需求。Dumbo2 的 ACS 子协议由 PRBC 广播与 MVBA 共识两部分组成：节点并行执行 PRBC 实例；当收集到 $n-f$ 个 PRBC 完成证明后，将其作为 MVBA 的输入。由于进入 MVBA 的提案数固定为 $n-f$，剩余至多 $f$ 个诚实节点的 PRBC 实例不会进入当前轮次的决定集合。本文在此基础上设计改进机制，通过监听其抛出的异步事件，将未及时进入 MVBA 的有效广播结果缓存，并在后续轮次重新注入。

== 复用前提与复用对象的界定

并非所有历史广播结果都能安全地进行跨轮次复用。以经典的可靠广播（RBC）为例，其仅保证“最终一致投递”，但不天然产出可供任意诚实节点独立验证的公开证明。若恶意节点伪造轻量级引用，诱导系统复用未达到可用性状态的 RBC 数据，将直接破坏系统的整体正确性。

因此，跨轮次复用的核心前提是：目标对象的广播子协议必须能够产出公开可验证的证据（例如阈值签名或完成证书）。满足这一要求的典型协议是 PRBC（Provable Reliable Broadcast）@guoDumboFasterAsynchronous2020。PRBC 完成时生成的证书，使节点无需重新执行广播交互即可确认该条目的可用性。

对于无法生成可验证完成证书的广播路径，本文的跨轮次复用机制不能直接适用。不过，在某些协议中（比如HoneyBadger BFT），可将原有的 RBC 替换为 PRBC 以满足复用条件。由于 PRBC 完全满足 RBC 的正确性性质，该替换在安全性上是可行的。但由于 PRBC 的开销更大，这可能会对协议性能产生一定影响。

== 核心数据结构与提案编码

为使历史广播结果能够被安全引用，每个可复用条目被赋予稳定的全局唯一标识与证明绑定。一个完整条目（Item）定义为：

$ upright("Item") = (e, i, h, pi, upright("id")) $

其中 $e$ 表示该广播发起的来源轮次，$i$ 表示发送者节点编号，$h$ 为广播负载的密码学摘要（如 Merkle Root 或 Hash），$pi$ 为对应的可用性完成证明（如阈值签名），$upright("id")$ 为用于本地哈希表索引的轻量级标识。其中 $upright("id")$ 仅用于快速命中，不承担安全校验功能。系统的安全性的由 $(e, i, h, pi)$ 之间的强绑定关系保证。

每轮输入给 ACS 协议的提案被编码为如下的统一格式：

$ upright("Proposal")_e = chevron.l upright("NewPayload")_e, {upright("Item")_1, upright("Item")_2, ...} chevron.r $

其中 $"NewPayload"_e$ 为该轮次的新交易负载，${upright("Item")_1, upright("Item")_2, ...}$ 为可选的历史引用条目集合，其数量上限由参数 $K$（单轮复用上限）决定。

通过用轻量级引用来代替完整负载进行提案传输，可显著降低通信开销。同时，由于提案格式统一，复用机制对底层 ACS 协议是透明的，其正确性可直接在 ACS 的输入/输出语义层面加以讨论。

== 生命周期管理与重提策略

为控制内存溢出并避免无限重提，复用机制为每个条目引入了有限生命周期管理。复用池（Reuse Pool）中的每个缓存条目在其生命周期内经历四种状态转换：

1. *已缓存（Cached）*：条目在规定的截留窗口（Grace Window, $G$）内完成 PRBC 并生成证明，进入复用池；
2. *可重提（Proposable）*：尚未被成功纳入全局决定结果，且存活轮数未超限；
3. *已消费（Consumed）*：已通过某一轮提案被正式采纳并上链；
4. *已过期（Expired）*：存活轮数超过系统参数设定或因容量驱逐而被清理。

在下一轮构造提案时，节点依据参数 $K$（单轮复用上限），筛选状态为“可重提”的条目并执行去重检查，防止复用退化为无意义的冗余广播。

== 机制执行流程与算法描述

为了实现跨轮次复用机制与底层共识引擎的解耦，本文在架构设计上抽象出了一层事件驱动边界。我们将 ACS 核心协议视为一个内部执行严格串行逻辑、但向外异步抛出状态事件的“黑盒”状态机；而外层的宿主驱动程序则通过订阅并监听这些事件来推进跨轮复用与数据回取逻辑。

具体而言，为了支持复用机制，ACS 黑盒在执行时需向外暴露两类事件：

1. *广播完成事件（`PRBC_Complete`）*：当任意一个节点的 PRBC 实例在本地完成并生成可用性证明时立即触发。
2. *共识决定事件（`ACS_Decide`）*：当后端 MVBA 完成本轮共识，输出包含至少 $N-f$ 个提案的决定集合时触发。

@alg-acs 描述了 ACS 黑盒在满足上述接口要求下的事件抛出逻辑；

#algox(
  caption: "支持事件抛出的 ACS 黑盒接口伪代码",
  label-name: "alg-acs",
  [*Algorithm: ACS Consensus Core (Event Emitter)*],
  [*Input:*],
  [$quad$ `proposal`: $chevron.l `"NewPayload"`, `"Refs"` chevron.r$],
  [],
  [*Phase 1: Broadcast (PRBC)*],
  [1. Start PRBC broadcast for local `proposal`],
  [2. *Asynchronously for* each node $i$ in $P$:],
  [3. $quad$ Wait for PRBC instance from node $i$ to complete with proof $pi$],
  [4. $quad$ Emit_Event(`PRBC_Complete`, node $i$, payload $p$, proof $pi$)],
  [5.],
  [6. Wait until $n-f$ PRBC instances complete $arrow.r$ Vector $V$],
  [],
  [*Phase 2: Agreement (MVBA)*],
  [7. Start MVBA with input Vector $V$],
  [8. Wait for MVBA to output DecisionSet $D$],
  [9. Emit_Event(`ACS_Decide`, Epoch $e$, DecisionSet $D$)],
)

@alg-reuse 描述了驱动层如何利用这些事件来实现跨轮复用的完整生命周期。

#algox(
  caption: "跨轮次复用机制宿主驱动层伪代码",
  label-name: "alg-reuse",
  [*Algorithm: Host-Level Cross-Round Broadcast Reuse Mechanism*],
  [*State:*],
  [$quad$ `ReusePool`: Dictionary mapping `id` to `(payload, proof, state, epoch)`],
  [$quad$ `GraceWindow`: Time threshold $G$],
  [$quad$ `MaxReuse`: Limit parameter $K$],
  [],
  [*On Event: PRBC_Complete(node $i$, payload $p$, proof $pi$)*],
  [1. *If* system is currently within `GraceWindow` for Epoch $e$:],
  [2. $quad$ `ReusePool.add(id(p), (p, pi, "Proposable", e))`],
  [],
  [*On Event: ACS_Decide(Epoch $e$, DecisionSet $D$)*],
  [1. Start `GraceWindow` timer of duration $G$],
  [2. Wait for `GraceWindow` to expire],
  [3.],
  [4. *For* each proposal $chevron.l upright("NewPayload"), upright("Refs") chevron.r$ in $D$:],
  [5. $quad$ *For* each $upright("ref") = (e_r, i, h, pi, id)$ in $upright("Refs")$:],
  [6. $quad quad$ *If* $id$ not in `ReusePool`:],
  [7. $quad quad quad$ `payload` `"gets"` Asynchronous_Fetch(Source = $i$, hash = $h$)],
  [8. $quad quad quad$ *If* timeout or Verify($pi$, `payload`) == False:],
  [9. $quad quad quad quad$ Reject and drop $upright("ref")$],
  [10. $quad quad$ `ReusePool[id].state` `"gets"` "Consumed"],
  [11.],
  [12. Output valid payload to State Machine.],
  [13. Trigger_Epoch_Start($e+1$)],
  [],
  [*On Event: Trigger_Epoch_Start(Epoch $e+1$)*],
  [1. Evict entries in `ReusePool` where $e+1 - upright("entry.epoch") > upright("MaxTTL")$],
  [2. `selected_refs` `"gets"` Select up to $K$ "Proposable" items from `ReusePool`],
  [3. `new_txs` `"gets"` Fetch new transactions from Mempool],
  [4. Start ACS($e+1$) with input $chevron.l `"new_txs"`, `"selected_refs"` chevron.r$],
)

该跨轮复用机制（@alg-reuse）可归纳为以下四个阶段：

1. *广播截留（步骤 1-3）*：在 Epoch $e$ 的 ACS 决定输出后，在时长为 $G$ 的截留窗口内，将诚实但迟到的 PRBC 结果连同完成证明写入本地复用池。
2. *跨轮提案构造（步骤 14及 Start 事件）*：新一轮启动时，从复用池提取至多 $K$ 个未消费的历史引用，与新交易打包成统一提案作为 ACS 协议的输入。
3. *引用解析与拉取（步骤 6-10）*：当节点收到包含历史引用的共识输出时，首先查询本地池；若未命中则根据来源信息触发异步回取（Fetch）。只有通过 $pi$ 验证的原始负载才会被视为有效输入。
4. *状态回收（步骤 11及垃圾回收阶段）*：成功解析的引用被标记为已消费，同时清理超期的陈旧条目，确保内存安全。

== 安全性与活性分析

本机制作为宿主层优化，其引入未破坏原 ACS 协议的安全边界与活性保证。

=== 安全性论证

本机制的安全性基于引用的非替代性与强制验证逻辑。历史引用并非原始负载的等价物，节点在处理共识输出时，必须获取原始负载并依据随附的证明 $pi$ 进行强制校验（如算法1第9行）。由于可用性证明具有不可伪造性，拜占庭节点无法通过构造虚假引用来诱导诚实节点接受非法数据。此外，复用池仅接收历史上已产生全局证明的数据，并未改变底层协议关于“数据可恢复性”的数学假设。

=== 活性分析

根据 FLP 不可能定理 @fischerImpossibilityDistributedConsensus1985，在纯异步网络中任何确定性共识都无法同时保证安全性和活性，异步 BFT 因而依赖随机化组件（如共同硬币）以概率 1 终止。本机制不干涉这些组件推进，其对活性的唯一影响体现在延迟的权衡：

1. *Grace 窗口的延迟权衡*：截留窗口 $G$ 会在轮次切换间隙引入强制等待。该参数需根据网络延迟方差动态调优，以少量时延换取大幅吞吐增益。由于 $G$ 是确定性的有限常量，其不会破坏原协议的概率终止性（Probabilistic Termination）。
2. *回取（Fetch）的异步容错*：若全网因极端情况（如发送者掉线）无法恢复原始负载，同步阻塞将导致活性丧失。为此，本机制的 Fetch 路径被设计为带有超时的异步任务（如算法1第8-10行）。超时即放弃该引用，这种“尽力而为”的策略阻断了因局部历史数据缺失而导致全局协议停滞的风险。

综上所述，跨轮复用机制通过强化证明绑定保障了安全性，并通过合理的参数配置与异步处理维持了协议的活性。

= 实验设计与结果分析

// 约 2000 字

== 系统架构与实现

本文实现了一个 HoneyBadger/Dumbo 风格的异步 BFT 原型系统。为避免侵入并改写 ACS 内部的一致性决定语义，跨轮次复用机制被独立设计并部署在 ACS 输入边界与外层宿主调度程序之间。原型系统在架构上划分为以下三个层级：

1. *密码学与编码层*：负责底层哈希运算、Merkle 树构建、阈值加密以及基于阈值签名的可用性证明生成，完成“内联负载 + 引用集合”的统一序列化格式转换与合规性校验。
2. *协议层*：系统的共识内核，按照状态机推进 ACS 及其内部组件（如 PRBC、MVBA 或 ABA）的协议逻辑，其不直接感知具体的交易数据负载，仅对数据摘要或条目标识进行共识。
3. *驱动层与运行时*：负责节点生命周期管理、网络 I/O 收发调度、提案构造、复用池内存维护、异步回取（Fetch）逻辑触发以及实验指标的采样汇总。

在运行时的具体工程设计上，系统遵循第三章提出的事件驱动边界模型。ACS 模块被封装为通过异步通道（Async Channels）通信的独立共识黑盒。驱动层通过非阻塞监听 ACS 抛出的 `Send`、`Broadcast` 物理网络请求，以及 `PRBC_Complete`、`ACS_Decide` 等逻辑状态事件，来进行相应的网络转发与数据展开处理。

为了降低系统耦合度，本文在运行时与 ACS 之间进行了严格的数据解耦：ACS 黑盒不直接持有或处理原始交易数据，而是仅处理轻量级的条目标识 `item_id`。节点运行时在每轮持续生成交易并缓存至本地，仅将索引向量作为输入传递给 ACS。这种解耦设计具有显著的工程价值：无论输入是当前轮的新交易，还是带有证明的历史复用引用，对 ACS 而言均是语义透明的索引。原始负载的维护、历史引用的递归展开、以及缺失数据的回取逻辑均交由外层运行时独立处理，从而保证了复用机制在不同 ACS 后端上的通用性。

在组件实现方面，驱动层集成了专门的复用池。复用池在一轮决定结束后，于有限的 Grace 窗口内截留迟到但已完成的广播结果。为确保系统的活性与稳定性，复用池实施了严格的生命周期管理，对每轮可重提条目数、条目存活轮数和缓存总容量均设置了物理上界。

本文使用 Rust 语言实现了原型系统中的底层密码学组件、运行时驱动以及网络通信模块。为了验证机制的广泛适用性，系统接入了两个不同的 ACS 协议后端：

- *Dumbo ACS 后端*：复用了 Dumbo @guoDumboFasterAsynchronous2020 的 Python 实现作为共识内核，并对其底层密码学依赖进行了跨语言适配与封装。
- *FIN-style ACS 后端*：基于 Rust 语言原生实现了修改版的 FIN 协议 @duanFINPracticalSignaturefree2023 核心流派，将其广播阶段由原生的可靠广播（RBC）替换为具备可用性证明的 PRBC，从而提供原生的跨轮次复用支持。

== 提案编码与复用池的工程实现

本节介绍跨轮次复用机制在原型系统中的具体工程落地方案，重点阐述提案的序列化格式设计与复用池的内存管理。

=== 统一提案编码的序列化格式设计

提案格式为遵循第三章定义的统一结构，即包含以下两个主要字段：

1. *内联负载（Inline Payload）*：本轮新生成的交易原始数据。
2. *引用集合（Reference Set）*：一个包含多个历史条目元数据的列表。每个元数据项遵循第三章定义的五元组 $(e, i, h, \pi, upright("id"))$。

这种编码方式将复用机制显式地注入到共识协议的输入边界。在工程实现上，由于 ACS 只需处理这些元数据的哈希或标识，上层驱动可以在不解析原始交易负载的情况下完成共识推进，从而实现了“共识层轻量化”的目标。

=== 宿主边界与复用池管理

复用池被实现为一个带有 TTL（生存时间）限制和容量阈值的并发安全哈希表。其不仅承担缓存功能，还作为区分“ACS 黑盒”与“外层宿主”的逻辑边界。当驱动层监听到 ACS 抛出的 `Decided` 事件后，会执行以下操作：

- *解析引用*：驱动层遍历决定集合中的引用标识，查询本地复用池。
- *状态更新*：命中池子的条目被标记为已消费，防止在后续 epoch 中被重复提案。
- *异步回收*：开启一个后台协程，在 Grace 窗口结束后自动清理过期或溢出的条目，以防止内存开销随运行轮数无限增长。

=== 缺失数据回取（Fetch）的触发路径

仅靠本地缓存无法保证数据全集的恢复，因此本文在宿主层实现了一条独立于共识主路径的回取路径。

回取机制被设计为一种“按需触发”的异步任务。当驱动层发现 Decided 结果中的某个条目在本地复用池中缺失时，会立即根据引用携带的来源节点发起定向拉取请求。这一过程发生在共识内核之外，不会阻塞 ACS 后续轮次的开启或是共识链路的整体停滞。

== 实验环境与评测指标

=== 实验环境与配置

本文实验基于本地多进程架构构建，每个逻辑节点均作为独立的系统进程运行，采用 QUIC 作为主要传输协议，通过本地回环地址进行网络通信。

实验统一配置参数为：节点总数 $N=12$，最大容错数 $f=3$。测试涵盖了从低负载到高负载的多个区间，批处理规模（Batch Size）覆盖 $\{8, 12, 16, 24, 32, 48, 64\}$。对于跨轮次复用机制，其核心参数固定为：单轮重提上限 4，条目过期轮数 10，内存池容量 1024。每组实验运行 8 轮共识并重复执行 2 次，取平均值作为最终统计结果。

=== 评测指标定义

为了从多维度评估复用机制的性能，本文定义了以下四项核心指标：

1. *端到端吞吐量（`TPS_wall`）*：定义为按实际物理时间（Wall-clock Time）累计计算的交易交付效率。该指标反映了用户视角的端到端系统效率。
2. *共识阶段吞吐量（`TPS_acs`）*：仅统计驱动程序在 ACS 阶段的内部处理耗时，用于分析协议内核的推进效率。
3. *追踪通信成本（`bytes/tx`）*：定义为单笔已交付交易对应的驱动层逻辑通信字节数。其计算公式为：
$
  upright("bytes/tx") = frac(upright("send_payload") + upright("proposal_payload") + upright("proposal_proof"), upright("total_delivered_tx"))
$
该指标包含了驱动层发送的原始负载、提案负载及相应的可用性证明材料。本文采用该归一化指标而非总字节数，旨在精确衡量复用机制在交易量增长时对通信效率的真实影响。
4. *平均复用条目数*：统计实验周期内被成功纳入共识决定集合的历史条目数量。

本文选取 Dumbo ACS 与 FIN 风格 ACS 作为两个代表性后端，对比“复用开启”与“复用关闭”两种配置下的表现。实验场景主要分为以下三类：

- *高负载基准测试*：评估复用机制在理想局域网环境下的吞吐提升上限。
- *Grace 窗口敏感性测试*：固定批处理规模为 32，通过调节 `pool_grace_ms`（取值区间为 50ms 至 400ms），观察截留窗口对回收效率的影响。
- *受控扰动与边界测试*：引入慢诚实节点（发送延迟 80ms-150ms）、静默节点以及无效回取响应，验证系统在“诚实但迟到”场景及最小拜占庭场景下的鲁棒性。

== 高负载基准测试结果分析

@tbl_highload_pilot 展示了在 QUIC 网络环境下，复用机制对系统吞吐量及通信成本的影响。实验选取了三个代表性批处理规模（$b in \{16, 32, 48\}$）进行数据对比。

#thesis-table(
  columns: (1.2fr, 0.8fr, 1.2fr, 1.2fr, 1.1fr),
  header: ([后端], [批处理], [`TPS_wall` 提升], [`bytes/tx` 变化], [平均复用条目]),
  rows: (
    [Dumbo],
    [16],
    [+9.79%],
    [+11.26%],
    [21.0],
    [Dumbo],
    [32],
    [+10.13%],
    [+7.22%],
    [21.0],
    [Dumbo],
    [48],
    [+15.56%],
    [+2.04%],
    [21.0],
    [FIN-style],
    [16],
    [+21.90%],
    [+21.68%],
    [21.0],
    [FIN-style],
    [32],
    [+18.93%],
    [+13.91%],
    [21.0],
    [FIN-style],
    [48],
    [+19.12%],
    [+8.27%],
    [21.0],
  ),
  caption: "N=12, f=3, QUIC 高负载实验中复用开启相对基线的代表性变化幅度",
  label-name: "tbl_highload_pilot",
)

实验结果显示，跨轮次复用机制在两种协议后端上均表现出显著的吞吐量增益。其中，Dumbo 路径的端到端吞吐量提升区间为 7.80% 至 15.56%；而 FIN 风格路径的端到端吞吐量提升幅度维持在 16.54% 至 21.90% 之间。平均每轮回收的历史条目数稳定在 21.0，说明机制在回收“迟到广播成果”方面的有效性。

值得注意的是，尽管吞吐量显著增长，但单笔交易的追踪通信成本（`bytes/tx`）并未如预期般下降，反而出现了小幅上升。这表明，虽然复用机制成功将原本被浪费的带宽转化为有效吞吐，但携带历史引用及相关证明材料所引入的额外元数据开销，在当前的参数配置下尚未被交易总量的增长完全稀释。

== Grace 窗口敏感性分析

为了进一步探究截留窗口时间（Grace Window）对回收效率的影响，本文对 Dumbo 路径进行了参数敏感性实验，测试结果如 @tbl_grace_sensitivity 所示。

#thesis-table(
  columns: (1.1fr, 1.3fr, 1.3fr, 1.2fr),
  header: ([`pool_grace_ms`], [`TPS_wall` 均值], [`bytes/tx` 均值], [平均复用条目]),
  rows: (
    [50],
    [916.20],
    [682.97],
    [9.0],
    [100],
    [893.49],
    [688.33],
    [9.0],
    [200],
    [955.60],
    [673.95],
    [9.0],
    [400],
    [954.82],
    [675.17],
    [9.0],
  ),
  caption: "Dumbo 路径上 QUIC Grace 窗口敏感性试验结果",
  label-name: "tbl_grace_sensitivity",
)


实验数据显示，在本地多进程环境下，当 `pool_grace_ms` 从 50ms 调节至 400ms 时，系统的复用条目数始终稳定在 9.0 左右，端到端吞吐量（`TPS_wall`）在 890 至 955 之间小幅波动。

此处的复用条目数未随时间窗口延长而发生阶跃变化，主要是由本文采用的本地回环仿真环境（Localhost）物理特性所决定的。由于本地进程间通信缺乏真实的广域网物理抖动，网络延迟方差极低，各节点落后广播的送达时间高度集中。因此，50ms 的截留窗口已足以捕获几乎所有诚实节点因共识时序落后而产生的迟到广播。实验在 200ms 至 400ms 区间内吞吐量达到最优，说明中等强度的缓冲时间已足以在不拖紧共识推进频率的前提下，稳定实现截留收益。

== 网络扰动与边界故障场景分析

本文进一步模拟了真实网络中的慢诚实节点场景以及典型的拜占庭故障场景，旨在验证机制在非理想条件下的稳定性，结果如 @tbl_slow_honest_quick 所示。

#thesis-table(
  columns: (1.4fr, 1.1fr, 1.2fr, 1.1fr, 1.2fr),
  header: ([场景], [`TPS_wall` 提升], [`bytes/tx` 变化], [平均复用条目], [平均 fetch 观测]),
  rows: (
    [慢诚实 `none`],
    [+17.23%],
    [+13.83%],
    [21.0],
    [0.0],
    [慢诚实 `80ms`],
    [+19.14%],
    [+13.71%],
    [21.0],
    [0.0],
    [慢诚实 `150ms`],
    [+15.38%],
    [+15.14%],
    [21.0],
    [0.0],
    [静默节点],
    [+15.49%],
    [+16.33%],
    [21.0],
    [0.0],
    [无效 fetch 响应],
    [+15.75%],
    [+13.83%],
    [21.0],
    [0.0],
  ),
  caption: "FIN 风格路径在 QUIC 慢诚实与最小边界故障场景中的结果",
  label-name: "tbl_slow_honest_quick",
)

在慢诚实节点场景中（设置 80ms-150ms 的额外发送延迟），FIN 风格路径仍能保持 15% 以上的吞吐量提升，并未因个别节点的时序严重滞后而导致整体性能崩溃。在静默节点和恶意回取响应（Invalid Fetch Response）场景下，系统依然维持了约 15% 的性能增益，证明了复用机制对局部节点异常具有良好的免疫力。

需要说明的是，在当前实验设定的条目生命周期（10轮）内，平均 Fetch 观测值为 0.0。这意味着在当前的负载分布下，绝大多数复用条目均能通过本地缓存命中实现恢复。这一结果表明，本机制在提高吞吐量的同时，并未频繁触发昂贵的网络回取开销，其收益主要源于对本地闲置数据的有效利用。

== 实验结论与局限性说明

综合实验数据可以得出结论：跨轮次复用机制能够有效回收基于 ACS 架构中因时序问题产生的广播浪费，并将其稳定地转化为端到端吞吐量的提升。

受限于实验环境与时间，本研究仍存在以下局限：首先，当前测试主要基于 $n=12$ 规模的本地回环网络，在节点规模更大、延迟波动更剧烈的真实广域网（WAN）环境下，复用池的内存压力与回取路径的触发频率仍需进一步观察；其次，追踪通信成本的口径依赖于驱动层应用数据包统计，未来需通过网卡级（如 `tcpdump` 或 `eBPF`）抓包以获取更精确的物理网络层带宽占用数据；最后，对于回取路径（Fetch Path）在极端网络分区的丢包环境下的性能损耗，目前尚缺乏充分的实证数据支撑。

= 总结与展望

// 约 1000 字

== 总结与主要成果

本文针对基于异步公共子集（ACS）的 BFT 共识协议中，因广播与共识阶段严格串行而导致“诚实但迟到”的广播数据被丢弃的问题，设计并实现了一种跨轮次广播复用机制。

在机制设计与工程实现方面，本课题在不修改底层 ACS 协议一致性内核的前提下，构建了一套完整的缓存复用流程。该机制通过引入有限时长的 Grace 窗口截留历史提案，采用“内联负载+引用”的统一提案编码，并结合复用池的生命周期管理以及异步回取 （Fetch） 机制，实现了对迟到广播成果的安全回收。

在系统评估方面，本文基于 Rust 语言开发了原型系统，并在 $n=12$ 的多进程仿真环境中完成了对比实验。结果表明，该机制在接入 Dumbo 与 FIN 两种主流 ACS 后端时，均能将端到端吞吐量稳定提升 10% 至 20%。该方案为现有的串行异步共识系统提供了一种低侵入、易落地的性能优化途径。

== 展望：偏序关系的维护与未来工作

在研究过程中，本文观察到：广播浪费问题来源于于严格串行 ACS 结构对共识历史中偏序信息（Partial Order）的主动抛弃

近年来，学术界提出了一些完全并行的异步共识方案（如 Dumbo-NG 或基于 DAG 的 Narwhal and Tusk）。这些方案通过在协议底层维护多轮水位线或图结构等复杂的偏序关系，实现了广播与共识的完全解耦。在这种架构下，“迟到”的数据能被后续的偏序边直接引用，从根本上规避了带宽浪费问题。

不过，维护全局的偏序关系不可避免地会带来更高的系统状态复杂度和更复杂的元数据维护机制。相比之下，本文提出的跨轮复用机制，是在不引入复杂偏序逻辑的前提下，对经典串行 ACS 架构进行的一种局部性能补偿。能以较低的工程代价，对原本会被丢弃的广播成果进行回收。

在未来的研究工作中，可以考虑将该机制在真实的广域网环境中进行部署测试，进一步评估其在高延迟波动下的性能表现。
