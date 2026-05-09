#import "lib.typ": sdu-thesis, thesis-table
#import "utils.typ": algox, highload-tps-chart, slow-count-sweep-chart, thesis-figure
#import "@preview/cetz:0.5.2"

#show: sdu-thesis.with(
  title: "面向异步共识协议的广播数据跨轮次复用机制设计与实现",
  author: "刘振伟",
  school_id: "202200130086",
  school: "计算机科学与技术学院",
  major: "计算机科学与技术",
  grade: "2022级",
  supervisor: "高英梓",
  date: "2026年5月9日",

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

    本课题原型系统中的 Dumbo ACS 协议代码来自于开源社区，FIN-style ACS 协议黑盒的实现则参考了 JUMBO 论文的开源实现。

    祝愿所有帮助过我的人幸福快乐。

    本课题在设计与撰写过程中使用了生成式大语言模型辅助。
  ],

  appendix: [

    附录提供了正文第4章各项实验的详细绝对数值表。由于正文重点讨论各配置下的吞吐量（TPS）变化比率与机制表现趋势，具体的端到端绝对吞吐量、单轮延迟及追踪通信成本等底层指标详列于此。

    == A. 高负载基准测试补充数据

    @tbl_highload_tps 展示了 FIN 风格 ACS 与 Dumbo ACS 两种后端在复用开启与关闭两种配置下，端到端吞吐量（`TPS_wall`）随批处理规模的具体绝对数值变化。

    #thesis-table(
      columns: (0.7fr, 1fr, 1fr, 1fr, 1fr),
      header: ([批处理], [FIN `reuse_on`], [FIN `reuse_off`], [Dumbo `reuse_on`], [Dumbo `reuse_off`]),
      rows: (
        [32],
        [343],
        [276],
        [318],
        [255],
        [64],
        [687],
        [551],
        [641],
        [506],
        [128],
        [1,370],
        [1,109],
        [1,257],
        [1,022],
        [256],
        [2,735],
        [2,206],
        [2,502],
        [2,038],
        [512],
        [5,436],
        [4,403],
        [5,021],
        [4,007],
        [1,024],
        [10,695],
        [8,720],
        [9,980],
        [7,985],
        [2,048],
        [20,801],
        [16,836],
        [19,189],
        [15,532],
        [4,096],
        [39,263],
        [31,845],
        [36,380],
        [29,474],
        [8,192],
        [68,854],
        [56,122],
        [62,803],
        [52,270],
        [16,384],
        [108,320],
        [88,840],
        [98,729],
        [83,489],
        [24,576],
        [107,927],
        [90,178],
        [103,974],
        [87,324],
        [32,768],
        [125,082],
        [104,015],
        [124,658],
        [103,748],
        [49,152],
        [—],
        [—],
        [144,337],
        [124,705],
        [65,536],
        [165,708],
        [129,557],
        [—],
        [—],
        [98,304],
        [176,139],
        [157,713],
        [—],
        [—],
        [131,072],
        [170,837],
        [128,824],
        [—],
        [159,077],
        [196,608],
        [123,646],
        [124,474],
        [—],
        [—],
        [262,144],
        [100,008],
        [86,256],
        [—],
        [—],
      ),
      caption: "N=12, f=3, QUIC 环境下两种后端的端到端吞吐量（单位：TPS）。",
      label-name: "tbl_highload_tps",
    )


    @tbl_highload_latency 报告了高负载基准测试下各配置的单轮端到端延迟均值，用于辅助分析吞吐量在极大负载下出现衰减的超线性延迟成因。

    #thesis-table(
      columns: (0.7fr, 1fr, 1fr, 1fr, 1fr),
      header: ([批处理], [FIN `reuse_on`], [FIN `reuse_off`], [Dumbo `reuse_on`], [Dumbo `reuse_off`]),
      rows: (
        [32],
        [221 ms],
        [197 ms],
        [310 ms],
        [281 ms],
        [512],
        [234 ms],
        [199 ms],
        [325 ms],
        [302 ms],
        [4,096],
        [346 ms],
        [301 ms],
        [435 ms],
        [390 ms],
        [16,384],
        [851 ms],
        [775 ms],
        [1.01 s],
        [888 ms],
        [32,768],
        [1.56 s],
        [1.49 s],
        [1.63 s],
        [1.51 s],
        [65,536],
        [3.03 s],
        [3.09 s],
        [—],
        [—],
        [98,304],
        [4.76 s],
        [4.13 s],
        [—],
        [—],
        [131,072],
        [6.99 s],
        [7.49 s],
        [—],
        [5.93 s],
        [196,608],
        [15.51 s],
        [12.38 s],
        [—],
        [—],
        [262,144],
        [26.60 s],
        [25.32 s],
        [—],
        [—],
      ),
      caption: "单轮端到端延迟均值随批处理规模的变化",
      label-name: "tbl_highload_latency",
    )

    @tbl_highload_bytes 展示了追踪通信成本（`bytes/tx`）随批处理规模的变化，用于评估协议附加元数据的带宽分摊效应。

    #thesis-table(
      columns: (0.7fr, 1fr, 1fr),
      header: ([批处理], [FIN `reuse_on`], [FIN `reuse_off`]),
      rows: (
        [32],
        [573],
        [507],
        [128],
        [250],
        [263],
        [512],
        [170],
        [203],
        [2,048],
        [152],
        [191],
        [16,384],
        [149],
        [189],
        [32,768],
        [153],
        [188],
        [65,536],
        [152],
        [191],
        [98,304],
        [152],
        [183],
        [131,072],
        [153],
        [187],
        [196,608],
        [155],
        [194],
        [262,144],
        [155],
        [194],
      ),
      caption: "追踪通信成本（bytes/tx）随批处理规模的变化",
      label-name: "tbl_highload_bytes",
    )

    @tbl_highload_reuse 汇总了两种后端在代表性批处理规模下复用开启相对关闭的 TPS 增益百分比。

    #thesis-table(
      columns: (0.7fr, 1.2fr, 1.2fr),
      header: ([批处理], [FIN 复用增益], [Dumbo 复用增益]),
      rows: (
        [32],
        [+24.1%],
        [+24.7%],
        [256],
        [+24.0%],
        [+22.8%],
        [1,024],
        [+22.7%],
        [+20.1%],
        [4,096],
        [+23.3%],
        [+23.4%],
        [16,384],
        [+21.9%],
        [+18.3%],
        [32,768],
        [+20.3%],
        [+20.1%],
        [65,536],
        [+27.9%],
        [—],
        [98,304],
        [+11.7%],
        [—],
        [131,072],
        [+32.6%],
        [—],
        [196,608],
        [-0.7%],
        [—],
        [262,144],
        [+15.9%],
        [—],
      ),
      caption: "复用开启相对关闭的 TPS 增益比例",
      label-name: "tbl_highload_reuse",
    )

    == B. 节点规模可扩展性补充数据

    本组实验固定批处理规模 $b = 2048$，以排除单节点负载过大导致的资源崩溃，测试在 $N in {4, 8, 12, 16}$ 四种节点规模下系统的绝对吞吐量表现与复用增益比例。

    @tbl_scalability_tps 与 @tbl_scalability_reuse 分别展示了端到端绝对吞吐量变化与对应的增益比率。

    #thesis-table(
      columns: (0.7fr, 1fr, 1fr, 1fr, 1fr),
      header: ([节点数 $N$], [FIN `reuse_on`], [FIN `reuse_off`], [Dumbo `reuse_on`], [Dumbo `reuse_off`]),
      rows: (
        [4],
        [157,545],
        [164,460],
        [96,149],
        [77,211],
        [8],
        [118,066],
        [110,673],
        [87,911],
        [73,865],
        [12],
        [82,869],
        [75,514],
        [62,932],
        [54,299],
        [16],
        [49,354],
        [43,004],
        [40,531],
        [34,362],
      ),
      caption: "N=4,8,12,16 下的端到端吞吐量（b=2048, TPS）。",
      label-name: "tbl_scalability_tps",
    )

    #thesis-table(
      columns: (0.7fr, 1.2fr, 1.2fr),
      header: ([节点数 $N$], [FIN 复用增益], [Dumbo 复用增益]),
      rows: (
        [4],
        [-3.5%],
        [+24.5%],
        [8],
        [+6.7%],
        [+19.1%],
        [12],
        [+9.8%],
        [+15.9%],
        [16],
        [+14.8%],
        [+17.9%],
      ),
      caption: "不同节点规模下复用开启相对关闭的 TPS 增益比例",
      label-name: "tbl_scalability_reuse",
    )
    == C. Grace 窗口敏感性补充数据

    @tbl_grace_sensitivity_clean 记录了在本地多进程环境下，调整截留窗口时间（Grace Window）对系统吞吐量及复用条目数回收效率的影响。

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
      label-name: "tbl_grace_sensitivity_clean",
    )
  ],
)

= 绪论
// 约 2000 字

== 研究背景与问题

异步拜占庭容错（Byzantine Fault Tolerance, BFT）共识协议旨在容忍至多 $f$ 个节点发生任意故障的前提下，在网络消息延迟不存在上界的纯异步环境中，使所有诚实节点仍能就同一批交易或区块的顺序达成一致。与依赖同步或部分同步假设的经典协议（如 PBFT @castroPracticalByzantineFault2002）不同，异步 BFT 不依赖超时机制来判断节点失效，因而在网络条件剧烈波动、极易发生网络分区的广域网环境中具备天然的活性（Liveness）优势，更适合构建高可用的分布式系统 @YuanYongQuKuaiLianJiShuFaZhanXianZhuangYuZhanWang2016 @CengShiQinQuKuaiLianJiShuYanJiuZongShuYuanLiJinZhanYuYingYong2020。

基于异步公共子集（Asynchronous Common Subset, ACS）实现的异步 BFT 协议因其结构简洁、模块化程度高而受到广泛关注 @YuanYongQuKuaiLianGongShiSuanFaDeFaZhanXianZhuangYuZhanWang2018，代表性工作包括 HoneyBadger @millerHoneyBadgerBFT2016 与 Dumbo @guoDumboFasterAsynchronous2020 系列协议；设系统共由 $N$ 个节点组成，其中至多 $f$ 个节点可能发生拜占庭故障；经典的 ACS 协议通常划分为广播与共识两个严格串行的阶段：广播阶段负责使各节点的提案广泛可用，共识阶段则在此基础上从至少 $N-f$ 个提案中选出公共子集作为本轮输出。

然而，严格串行的结构带来了一个网络带宽浪费问题：一旦节点成功收集到至少 $N-f$ 个可用性证明，即可结束本轮广播阶段的等待并推进共识。此时，其余诚实节点（至多 $f$ 个）的广播进程仍在进行中。即使这些提案最终完成了网络传输并取得了可用性证明，也会因落后于当前的共识进度而被直接丢弃。对于这些“诚实但迟到”的广播负载，底层网络已经为其支付了全额的带宽成本，但共识层却未能对这些成果加以利用。其宏观结果表现为系统有效吞吐量的下降和广播冗余的增加；在系统负载较高或节点间计算与网络性能存在明显差异的部署环境中，这种资源浪费尤为突出。

== 研究意义

近年来，为解决上述串行阶段带来的性能瓶颈，学术界提出了多种完全并行的异步共识架构（如基于 DAG 的 Narwhal and Tusk     @danezisNarwhalTuskDAGbased2022 等）；然而，这类方法通常需要对协议进行颠覆性重构，大幅增加状态维护的复杂性 @ZhangLingYueYiBuGongShiXieYiYanJiuZongShu2024。

相比之下，在经典串行 ACS 架构基础上引入广播数据跨轮次复用机制，能够在不改变现有协议骨架与内部决定语义的前提下，有效回收被丢弃的迟到广播成果。这一思路将外层调度优化与底层共识引擎解耦，降低了工程实现难度，便于已有的异步 BFT 系统进行增量式平滑迁移，具有直接且迫切的工程参考价值。同时，随着区块链、联盟链以及分布式数据库等基础设施对高吞吐、低浪费特性的持续追求，此类轻量级、可落地的协议层带宽优化手段有其明显的应用意义。

== 研究目标与主要贡献

本文以串行 ACS 协议中的历史广播数据浪费问题为切入点，提出并实现了一种面向异步 BFT 的跨轮次广播复用方法，通过对“诚实但迟到”的数据进行缓存复用来降低带宽损耗并提升整体吞吐量。本文围绕该机制的协议设计、系统实现以及本地仿真评估展开工作，主要贡献包括：

1. *机制设计与安全性论证*：提出了一种面向串行 ACS 协议的跨轮次复用机制。将复用对象严格限定为“已取得可用性证明、但因时序落后未被采纳”的历史提案，通过引入生命周期截留窗口，确保复用机制作为宿主层逻辑不侵入 ACS 的决定语义，并在理论上维护了原协议的安全性与活性边界。
2. *原型系统实现*：围绕统一提案格式编码、缓存生命周期管理（Grace Window）、引用消费去重以及基于异步回取（Fetch）的缺失数据恢复等关键环节，对协议栈进行了端到端的设计与改造，并基于 Rust 语言完成了融合多语言 ACS 后端的原型系统开发。
3. *多维度实验评估*：在本地仿真环境中，针对高负载、截留敏感性及受控网络扰动等多种场景进行了对比实验。结果表明，在典型高负载设置下，跨轮次复用能够将系统端到端吞吐量稳定提升 10% 至 20%。

== 论文组织结构

本文后续章节安排如下：第二章回顾相关研究，梳理异步 BFT 协议的发展脉络和已有性能优化的学术尝试；第三章介绍跨轮次复用机制的系统模型、机制设计与安全性分析；第四章介绍原型系统实现与仿真实验设计，并对实验结果进行分析；第五章总结全文并讨论未来的研究方向。

= 背景与相关工作

// 约 2000 字
共识协议，即分布式系统中多个节点就某个数据或状态达成一致意见的规则与机制 @LiuYiZhongQuKuaiLianGongShiJiZhiYanJiuZongShu2019 @YuanYongQuKuaiLianJiShuFaZhanXianZhuangYuZhanWang2016，其中 BFT 共识协议保证了在有节点作恶的情况下仍然保证协议正确。而从时间假设来说，又可以分为：同步、弱同步与异步共识协议，异步共识协议不需要通过超时机制来判断对方是否失效，从而能够在网络条件极不稳定时仍保持活性保证。

换言之，异步 BFT 共识协议在至多 $f$ 个节点任意作恶、网络消息延迟无上界的条件下，仍能确保诚实节点对同一批交易或区块顺序达成一致。

在纯异步网络模型下，由于无法使用超时机制来判断节点是否发生崩溃或拜占庭故障，共识协议的设计面临着极其严苛的理论限制（如 FLP 不可能定理）。传统的解决思路是引入随机化操作，允许系统以概率为 1 终止。

== ACS 与异步 BFT

自 HoneyBadgerBFT @millerHoneyBadgerBFT2016 首次证明异步 BFT 在实际广域网中的可行性以来，基于 ACS 范式的架构便成为了该领域的主流。ACS 允许 $N$ 个节点各自提出输入值，并确保所有诚实节点最终输出完全相同的、包含至少 $N-f$ 个提案的公共子集。文献@millerHoneyBadgerBFT2016 指出：通过结合门限加密技术，ACS 可被直接转化为异步原子广播（Asynchronous Atomic Broadcast, AAB），进而构建完整的共识账本。

ACS 的早期理论来源可以追溯到 Ben-Or、Kelmer 与 Rabin 对异步安全计算和公共子集问题的研究 @ben-orAsynchronousSecureComputations1994。@ben-orAsynchronousSecureComputations1994 中提出的 ACS 范式（其核心结构由 $N$ 个可靠广播（RBC）实例与 $N$ 个异步二元拜占庭共识（ABA）实例组成）被许多文献称之 BKR94 范式。HoneyBadgerBFT 便是该范式的典型代表。

另一个比较主要的范式被称之为 CKPS01 @cachinSecureEfficientAsynchronous2001 范式，由 Cachin 等人于 2001 年提出，该范式利用多值拜占庭共识（MVBA）代替了复杂的 $N$ 个 ABA 实例。正如 @millerHoneyBadgerBFT2016 中所指出的：在早期实现中，CKPS01 范式要求将完整的提案负载直接输入给 MVBA，导致极高的通信复杂度。

Dumbo 协议 @guoDumboFasterAsynchronous2020 对 CKPS01 范式做出了关键突破。Dumbo 结合了两种范式的优点，通过引入可证明可靠广播（Provable Reliable Broadcast, PRBC），在广播阶段完成大负载的传输与可用性证明，随后仅将轻量级的证明（Proof）作为向量输入给后端的 MVBA。这种设计将 ACS 的一致性阶段从“对每个提案进行 $N$ 次二值决定”转化为“围绕一个已验证的候选向量达成一次决定”，从而显著降低了延迟并提升了吞吐量。

Dumbo2 ACS 结构中的 MVBA 是作为一个可插拔的“黑盒”组件存在的，因此可以任意替换，有诸多研究（如 Dumbo-MVBA @luDumboMVBAOptimalMultivalued2020、sDumbo @guoSpeedingDumboPushing2022、以及基于无签名设置的 FIN @duanFINPracticalSignaturefree2023）聚焦于优化 MVBA 内部的密码学开销或通信轮数。由于本文的跨轮次复用机制作用于 ACS 的输入边界而非内部逻辑，因此在后续设计中，上述 MVBA 变体均可视作透明的底层黑盒。此外，PACE @zhangPACEFullyParallelizable2022 等工作通过引入可重提的一致性框架（RABA）对 BKR94 结构进行了改良，这些工作在广义上均属于经典串行 ACS 的演进。

基于有向无环图（DAG）的异步 BFT 协议绕开了 ACS，如 DAG-rider @keidarAllYouNeed2021；2022 年的 Narwhal and Tusk @danezisNarwhalTuskDAGbased2022 通过将 Mempool 协议和共识协议进行并行解耦，获得了很好的性能。2025 年的 Mysticeti @babelMysticetiReachingLatency2025 则将 DAG 路径的延迟推至消息复杂度下界。基于 DAG 的协议实现相比基于 ACS 的协议在实现上会更复杂。

国内方面，异步 BFT 方向也已出现一些面向具体问题的改进工作。例如，@WangYaoQiGuaYongYuQuKuaiLianDeGaoXiaoYiBuBaiZhanTingRongCuoSuanFa2023 提出 PenguinBFT，主要针对异步共识中的通信与交易恢复开销进行优化；@ZhouYiKeIDumboQuanLiuChengYinSiBaoHuYiBuBaiZhanTingGongShiXieYi2025 提出 IDumbo，在 DumboBFT 框架下进一步融入全流程隐私保护机制。

== 并行化架构与带宽利用

经典的 ACS 结构（无论是 HoneyBadger 还是 Dumbo）严格遵守“广播完毕后触发共识”的串行两阶段执行逻辑。正如 DispersedLedger @yangDispersedLedgerHighthroughputByzantine2022 论文中所指出的，这种严格串行会造成系统资源的阶段性闲置：广播阶段主要受限于带宽资源，而共识阶段（尤其是涉及复杂密码学运算的 ABA 或 MVBA）主要受限于 CPU 与时间资源。

为了打破这种串行瓶颈，学术界提出了多种并行化方案。

第一种思路是弱化广播原语，在广播阶段不强制要求数据全网可达，而是在共识决定输出后，增加一个异步的回取（Retrieval）阶段来下载缺失数据。DispersedLedger 和 sDumbo @guoSpeedingDumboPushing2022 都使用了类似的优化方法。

第二种思路是将广播与共识完全解耦，通过流水线（Pipelining）设计同时推进多轮共识。Dumbo-NG @gaoDumboNGFastAsynchronous2022 通过维护多轮次的水位线（Watermark）来实现这一目标。JUMBO @chengMathsfJUMBOJUMBOFully2025 则在 Dumbo-NG 框架的基础上，通过签名聚合技术将通信复杂度从 $O(n^3)$ 降至 $O(n^2)$，
为此类并行化方案的后续扩展提供了重要的工程参考

第三种方案是放弃 ACS 结构，使用新的共识范式。以 Narwhal and Tusk @danezisNarwhalTuskDAGbased2022 为代表的 DAG 共识协议，通过在底层内存池节点间维护图结构的偏序关系，实现了广播与共识的完全并发。Bolt-Dumbo Transformer @luBoltdumboTransformerAsynchronous2022 则在 DAG 与传统 ACS 之间搭建了通用适配框架，实现了乐观路径与异步回退的灵活切换。

这些并行化方案往往以增加协议状态机复杂度和元数据维护开销为代价。本文的研究主要是对传统且部署广泛的串行 ACS 结构进行局部优化，不涉及对共识内核进行并发重构，

== 迟到广播与带宽浪费问题

在严格串行的 ACS 架构中，系统推进必须满足活性要求：只要节点收集到 $N-f$ 个合法的广播证明，就必须立即进入共识阶段，而不能无限期等待所有 $N$ 个提案完成（以防止拜占庭节点因拒不发包而导致系统停滞）。这一机制必然导致一个副作用：本轮共识中，剩下至多 $f$ 个诚实节点的广播提案即使最终到达，也会因时序落后而被系统丢弃，造成严重的带宽浪费。

并行的 ACS 协议则不会有这种浪费问题。

DispersedLedger @yangDispersedLedgerHighthroughputByzantine2022 对此问题有过深入探讨。在基于 BKR94 范式的 HoneyBadger 中，节点一旦收到 $N-f$ 个 RBC 完成消息，便会向本地所有的 $N$ 个 ABA 实例投出初始票。在网络同质性较好的情况下，其余 $f$ 个 RBC 仍有较大概率在 ABA 结束前完成全局终止。然而，在网络波动较大的情况下，浪费依然严重。为此，@yangDispersedLedgerHighthroughputByzantine2022 提出了 `internodelinking` 机制：在消息头中维护向量与水位线（本质上是提取并维护一种轻量级的偏序信息），使后续节点能够据此计算出历史消息的合法性并将其链入主账本。

需要指出的是，`internodelinking` 机制深度修改了 BKR94 范式内部协议，其耦合度极高。对于基于 CKPS01 范式（即 PRBC + MVBA）的 Dumbo 风格协议而言，这种深度的内部结构修改难以直接迁移。针对这一痛点，本文提出一种非侵入式的跨轮次复用机制，旨在无需引入复杂偏序状态机、不改动 MVBA 内部语义的前提下，解决串行 ACS 中的广播浪费问题。

= 跨轮次复用机制的设计与实现

// 约 3000 字

== 问题建模与系统假设

本文采用与 HoneyBadgerBFT @millerHoneyBadgerBFT2016 和 Dumbo @guoDumboFasterAsynchronous2020 相同的系统模型，具体假设如下：

- *节点与网络*：设系统中有 $n$ 个节点集合 $P = {P_1, P_2, ..., P_n}$。节点的身份与公钥信息公开可信。网络为纯异步认证点对点网络，任意两个节点间存在可靠的认证信道；攻击者可以任意延迟、重排或丢弃消息，但诚实节点之间发送的消息若经历无限时间等待，最终必然送达。
- *故障模型*：系统中最多存在 $f$ 个静态的拜占庭故障节点（满足 $n >= 3f + 1$）。攻击者在协议开始前可完全控制这 $f$ 个节点，获取其内部状态，并能在协议执行期间使其发生任意偏离协议的恶意行为。

在该模型下，我们旨在构造一个 $n$ 节点参与的异步原子广播（Asynchronous Atomic Broadcast）协议。协议按连续的轮次（Epoch）推进，每轮结束后系统输出一批新的交易并追加到全局已提交日志中。该协议需以压倒性概率满足以下性质：

- *一致性（Agreement）*：如果某个诚实节点输出交易序列 $v$，那么所有诚实节点最终都会输出 $v$；
- *全序性（Total Order）*：如果两个诚实节点分别输出历史日志序列 $chevron.l v_0, v_1, ..., v_j chevron.r$ 和 $chevron.l v'_0, v'_1, ..., v'_{j'} chevron.r$，那么对于所有 $i <= min(j, j')$，必定满足 $v_i = v'_i$；
- *抗审查性（Censorship Resilience）*：如果某笔交易被 $n - f$ 个诚实节点作为输入提交，那么最终每个诚实节点都会在日志中输出该交易。

我们采用与 HoneyBadgerBFT @millerHoneyBadgerBFT2016 类似的构造思路，即先实现异步公共子集（ACS），再结合门限加密将 ACS 转化为原子广播。该 ACS 协议需满足以下性质：

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

如 @reuse-item-fsm 所示：为控制内存溢出并避免无限重提，每个条目引入了有限生命周期管理。复用池中的每个缓存条目在其生命周期内经历四种状态转换：

1. *已缓存（Cached）*：条目在规定的截留窗口（Grace Window, $G$）内完成 PRBC 并生成证明，进入复用池；
2. *可重提（Proposable）*：尚未被成功纳入全局决定结果，且存活轮数未超限；
3. *已消费（Consumed）*：已通过某一轮提案被正式采纳并上链；
4. *已过期（Expired）*：存活轮数超过系统参数设定或因容量驱逐而被清理。

#thesis-figure(
  caption: [复用池中广播条目（Item）的生命周期状态转换图],
  label-name: "reuse-item-fsm",
)[
  #cetz.canvas({
    import cetz.draw: *

    let p-start = (-3, 0)
    let p-cached = (0, 0)
    let p-proposable = (5, 0)
    let p-consumed = (9, 2.5)
    let p-expired = (9, -2.5)

    circle(p-cached, name: "s1")
    content("s1", text(font: ("Times New Roman", "SimSun"), size: 10pt)[*已缓存*\ (Cached)])

    circle(p-proposable, name: "s2")
    content("s2", text(font: ("Times New Roman", "SimSun"), size: 10pt)[*可重提*\ (Proposable)])

    circle(p-consumed, name: "s3")
    content("s3", text(font: ("Times New Roman", "SimSun"), size: 10pt)[*已消费*\ (Consumed)])

    circle(p-expired, name: "s4")
    content("s4", text(font: ("Times New Roman", "SimSun"), size: 10pt)[*已过期*\ (Expired)])

    // Start -> Cached
    line(p-start, "s1", mark: (end: "stealth"))
    content((-2.5, 0.6), text(font: ("Times New Roman", "SimSun"), size: 9pt)[截留窗口内完成 PRBC])

    // Cached -> Proposable
    line("s1", "s2", mark: (end: "stealth"))
    content((2.5, 0.4), text(font: ("Times New Roman", "SimSun"), size: 9pt)[新一轮次开启])

    // Proposable -> Consumed (倾斜文本，与连线平行)
    line("s2", "s3", mark: (end: "stealth"))
    content((6.2, 1.8), text(font: ("Times New Roman", "SimSun"), size: 8pt)[被共识决定采纳])

    // Proposable -> Expired (倾斜文本，与连线平行)
    line("s2", "s4", mark: (end: "stealth"))
    content((6.2, -1.8), text(font: ("Times New Roman", "SimSun"), size: 8pt)[存活轮数超限])
  })
]

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

== 系统架构与实现

本文实现了一个 HoneyBadger/Dumbo 风格的异步 BFT 原型系统。为避免侵入 ACS 内部的一致性决定语义，跨轮次复用机制被独立设计，部署于 ACS 输入边界与外层宿主调度程序之间。在架构上，原型系统划分为以下三个层级：

1. *密码学与编码层*：负责底层哈希运算、Merkle 树构建、阈值加密及基于阈值签名的可用性证明生成，并完成序列化格式转换与合规性校验。
2. *协议层*：按照状态机模型推进 ACS 及其内部组件的共识协议逻辑。
3. *驱动层与运行时*：负责节点生命周期管理、网络 I/O 收发调度、提案构造、复用池内存维护、异步回取（Fetch）逻辑触发以及实验指标的采样汇总。

在具体工程设计上，系统遵循第三章提出的事件驱动边界模型。ACS 模块被封装为通过异步通道（Async Channels）通信的独立共识黑盒；驱动层通过非阻塞监听 ACS 抛出的 `Send`、`Broadcast` 等物理网络请求，以及 `PRBC_Complete`、`ACS_Decide` 等逻辑状态事件，完成相应的网络转发与数据展开处理。复用池则实现为一个带有 TTL（生存时间）限制与容量阈值的并发安全哈希表。

系统的整体架构如 @fig_arch 所示。每一轮次中，提案构造模块从交易池和本地复用池中分别取新交易与历史引用，按第三章所述统一提案格式构造本轮输入，再由驱动层将其注入 ACS 以启动新一轮共识。共识执行过程中，ACS 向外层抛出两类异步事件：`ProposalAvailable`（PRBC 完成并产出可用性证明的提案）被存入 ProposalStore；`Decided`（MVBA 达成的全局决定集合）则触发区块组装流程——驱动层从 ProposalStore 取出被选中的提案，送入区块组装模块。

当驱动层监听到 `Decided` 事件后，将依次执行以下操作：

- *解析引用*：遍历决定集合中的引用标识，查询本地复用池。
- *状态更新*：命中池中的条目被标记为已消费，以防在后续 epoch 中被重复提案。
- *异步回收*：启动后台协程，在 Grace 窗口结束后自动清理过期或溢出的条目，防止内存开销随运行轮数无限累积。

区块组装模块识别提案中的历史引用部分后，首先查询本地复用池以获取原始数据；若本地未命中，则触发 Fetch 模块，向来源节点发起异步回取。回取机制采用"按需触发"设计：当驱动层在 `Decided` 结果中发现某条目在本地缺失时，立即根据引用携带的来源信息发起定向拉取。整个过程发生在共识内核之外，不阻塞 ACS 后续轮次的开启，也不影响共识链路的整体推进。

所有提案数据（新交易与解析完成的引用数据）经 TPKE 解密后拼装为最终区块，提交给状态机。本轮结束后，ProposalStore 中未被选中的提案（若其 PRBC 在 Grace 窗口内完成）由驱动层缓存至复用池，供后续轮次引用。

#thesis-figure(
  caption: [系统整体架构示意图],
  label-name: "fig_arch",
)[
  #image("arch.svg", width: 100%)
]

= 实验设计与结果分析

// 约 2000 字

== 实验环境与评测指标

本文实验基于本地多进程架构构建，每个节点均作为独立的系统进程运行，采用 QUIC 作为主要传输协议，通过本地回环地址进行网络通信。

实验统一配置参数为：节点总数 $N=12$，最大容错数 $f=3$。对于跨轮次复用机制，其参数固定为：单轮重提上限 4，条目过期轮数 10，内存池容量根据 Batch Size 规模，在 $b <= 16384$ 时为 4096，$b >= 24576$ 时提升至 524288。每组实验运行 4 至 6 轮共识并重复执行 2 至 3 次，取平均值作为最终统计结果。

为了从多维度评估复用机制的性能，本文使用以下四项指标：

1. *端到端吞吐量（`TPS_wall`）*：按实际物理时间（Wall-clock Time）累计计算的交易交付效率。反映用户视角的端到端系统效率。
2. *追踪通信成本（`bytes/tx`）*：单笔已交付交易对应的驱动层逻辑通信字节数。其计算公式为：
$
  upright("bytes/tx") = frac(upright("send_payload") + upright("proposal_payload") + upright("proposal_proof"), upright("total_delivered_tx"))
$
该指标包含了驱动层发送的原始负载、提案负载及相应的可用性证明材料。采用该归一化指标而非总字节数，旨在精确衡量复用机制在交易量增长时对通信效率的真实影响。
3. *平均复用条目数*：统计实验周期内被成功纳入共识决定集合的历史条目数量。

== 高负载基准测试的分析

高负载基准测试评估复用机制在理想局域网环境下的吞吐提升上限。实验将批处理规模从 32 几何级增至 262144，对比复用开启与关闭两种配置下的表现。Dumbo 后端在 $b >= 65536$ 时因运行时内存限制退出。

@fig_highload_tps 展示了 FIN 与 Dumbo 两种后端在不同批处理规模下的绝对吞吐量变化趋势，@tbl_reuse_gain 则给出对应的吞吐增益及通信开销统计。

#thesis-figure(
  caption: [高负载场景下批处理规模与端到端吞吐量的关系],
  label-name: "fig_highload_tps",
)[
  #highload-tps-chart()
]

#thesis-table(
  columns: (0.9fr, 1.2fr, 1.2fr, 1fr),
  header: ([批处理规模], [FIN 复用增益], [Dumbo 复用增益], [`bytes/tx` 差值]),
  rows: (
    [32],
    [+24.1%],
    [+24.7%],
    [+66],
    [256],
    [+24.0%],
    [+22.8%],
    [-26],
    [1,024],
    [+22.7%],
    [+20.1%],
    [-37],
    [4,096],
    [+23.3%],
    [+23.4%],
    [-40],
    [16,384],
    [+21.9%],
    [+18.3%],
    [-40],
    [32,768],
    [+20.3%],
    [+20.1%],
    [-35],
    [65,536],
    [+27.9%],
    [—],
    [-39],
    [98,304],
    [+11.7%],
    [—],
    [-31],
    [131,072],
    [+32.6%],
    [—],
    [-34],
    [196,608],
    [-0.7%],
    [—],
    [-39],
    [262,144],
    [+15.9%],
    [—],
    [-39],
  ),
  caption: "不同批处理规模下跨轮次复用的吞吐增益与通信开销变化（N=12）",
  label-name: "tbl_reuse_gain",
)

FIN 与 Dumbo 在可对比范围内（$b <= 32768$）的增益曲线高度一致，最大偏差不超过 5%。这表明复用收益主要来自宿主层的时序差异截留，而非特定 ACS 实现的细节。

增益数据呈现出三个区间。在 $b <= 32768$ 的中低负载段，增益稳定于 $+20.3%$ 至 $+24.1%$，对批处理规模的变化不敏感。当 $b$ 增至 65536 至 131072 时，增益进一步升至 $+27.9%$ 至 $+32.6%$：此区间内共识决策速度与 PRBC 完成速度之间的时序差距扩大，被当前轮次"落下"的诚实广播增多，复用回收的边际收益随之达到峰值。至 $b = 196608$ 时，单提案 Merkle shard 约 12 MB，CPU 与内存带宽成为各节点的共同瓶颈，PRBC 实例几乎同步完成，复用池的管理开销无数据可回收，增益短暂转负（$-0.7%$）。$b = 262144$ 时更大的负载重新制造了节点间时序差异，增益回升至 $+15.9%$，但已无法回到中低负载时的稳定水平。

通信开销方面，在极小批处理规模（$b=32$）下，复用引入的证明与引用元数据无法被仅 32 笔新交易充分稀释，每笔交付交易的追踪通信成本增加 66 bytes。随着批处理规模增大，回收的迟到交易以近乎零增量的通信成本计入总交付量，$b >= 256$ 后 `bytes/tx` 差值即转负，$b >= 4096$ 后稳定在约 $-39$ bytes/tx。

各批处理规模下的绝对吞吐量、轮延迟及通信效率详细数据见附录。

== 节点规模可扩展性分析

节点规模扩展测试固定批处理规模 $b=2048$，在 $N in {4, 8, 12, 16}$ 四种规模下对比 FIN 与 Dumbo 两种后端的复用表现，结果如 @tbl_reuse_scale 所示。

#thesis-table(
  columns: (0.9fr, 1.2fr, 1.2fr),
  header: ([节点数 $N$], [FIN 复用增益], [Dumbo 复用增益]),
  rows: (
    [4],
    [-3.5%],
    [+24.5%],
    [8],
    [+6.7%],
    [+19.1%],
    [12],
    [+9.8%],
    [+15.9%],
    [16],
    [+14.8%],
    [+17.9%],
  ),
  caption: "不同节点规模下跨轮次复用的吞吐增益（b=2048）",
  label-name: "tbl_reuse_scale",
)

FIN 后端的复用增益从 $N=4$ 时的 $-3.5%$ 单调攀升至 $N=16$ 时的 $+14.8%$。$N=4$ 时，ACS 在约 50ms 内即可完成所有提案的收集与决策，几乎没有广播数据因时序落后而被排除；复用池的维护开销（引用编码、生命周期管理、去重检查）成为纯成本，吞吐量微降。节点数增至 8、12、16 后，各节点 PRBC 实例因调度与网络延迟差异而"迟到"的概率持续上升，ACS 每轮从 $n-f$ 个最快完成者中决策，被排除在外的诚实提案相应增多，复用回收的价值随之增长。

Dumbo 后端呈现相同的上升趋势，但在 $N=4$ 时仍保持 $+24.5%$ 的正收益。差异源于 Dumbo 的 Python 运行时在高并发消息处理上存在更大的时序抖动，即便在小规模场景下也能为复用机制持续提供回收素材。

各节点规模下的绝对吞吐量（FIN 复用关闭下从 $N=4$ 时的 164,460 TPS 降至 $N=16$ 时的 43,004 TPS，呈超线性下降，体现 $O(N^2)$ 消息复杂度的影响）及两种后端的横向对比数据见附录。

== 网络传输受控扰动测试

本测试通过三类扰动验证复用机制在非理想条件下的鲁棒性：固定传输延迟（每条消息附加 10/25/50 ms 固定额外延迟）、随机传输抖动（每帧消息随机附加 $0 tilde J$ ms 均匀抖动）和慢诚实节点（pid=11，额外延迟 80/150/300 ms）。实验采用 FIN 后端，$N=12$，$b=1024$，每组运行 6 轮共识并重复 3 次，结果如 @tbl_network_faults 所示。

#thesis-table(
  columns: (1.3fr, 1fr, 1fr, 1fr),
  header: ([场景], [`reuse_off` TPS], [`reuse_on` TPS], [复用增益]),
  rows: (
    [无扰动],
    [42,249],
    [47,318],
    [+12.0%],
    [固定延迟 10 ms],
    [24,318],
    [28,723],
    [+18.1%],
    [固定延迟 25 ms],
    [17,268],
    [21,356],
    [+23.8%],
    [固定延迟 50 ms],
    [11,102],
    [13,675],
    [+23.2%],
    [随机抖动 10 ms],
    [29,752],
    [34,451],
    [+15.8%],
    [随机抖动 25 ms],
    [24,108],
    [28,340],
    [+17.5%],
    [随机抖动 50 ms],
    [17,296],
    [21,462],
    [+24.1%],
    [慢诚实节点 80 ms],
    [44,559],
    [45,585],
    [+2.3%],
    [慢诚实节点 150 ms],
    [43,348],
    [47,209],
    [+8.9%],
    [慢诚实节点 300 ms],
    [43,369],
    [46,988],
    [+8.3%],
  ),
  caption: "固定传输延迟与随机抖动下 FIN 后端的吞吐量变化（b=1024, N=12）。",
  label-name: "tbl_network_faults",
)

固定延迟场景中，绝对吞吐量随延迟增大急剧下降（50 ms 延迟时仅为无延迟时的 26.4%），但复用增益从 $+12.0%$ 单调上升至 $+23.2%$。随机抖动呈现完全一致的走势，50 ms 抖动下复用增益达到所有场景的最高值 $+24.1%$。这两组结果共同说明，复用增益的驱动因素是"迟到"广播的总量，而非迟到产生的具体原因。

慢诚实节点场景揭示了 ACS 机制的一个内在特性。在复用关闭配置下，单节点以额外 80 ms 延迟发送时，系统绝对吞吐（44,559 TPS）反而高于无慢节点基线（42,249 TPS）。ACS 仅需收集 $n-f=9$ 个最快的 PRBC 完成信号即可决策，慢节点被主动排除，其延迟不仅不拖累共识进度，还因减少了 TPKE 解密数量而带来轻微提速。这一效应在慢节点延迟达到 300 ms 时仍然成立。在复用开启条件下，慢节点的迟到数据被 Grace 窗口截留并在后续轮次中回收，系统吞吐在 80 ms 至 300 ms 的延迟范围内稳定保持 $+2.3%$ 至 $+8.9%$ 的增益。

为进一步考察慢节点数量对复用收益的影响，实验固定额外延迟为 150 ms，将慢诚实节点数从 0 逐级增至 12，结果如 @fig_slow_count_sweep 与 @tbl_slow_count_sweep 所示。

#thesis-figure(
  caption: [慢诚实节点数量增加时的吞吐量与复用增益变化],
  label-name: "fig_slow_count_sweep",
)[
  #slow-count-sweep-chart()
]

#thesis-table(
  columns: (1.3fr, 1fr, 1fr, 1fr),
  header: ([慢节点数], [`reuse_off` TPS], [`reuse_on` TPS], [复用增益]),
  rows: (
    [0],
    [41,903],
    [42,346],
    [+1.1%],
    [1],
    [43,348],
    [47,209],
    [+8.9%],
    [2],
    [42,850],
    [40,216],
    [−6.1%],
    [3],
    [43,408],
    [40,392],
    [−6.9%],
    [4],
    [9,187],
    [11,936],
    [+30.0%],
    [8],
    [5,602],
    [7,046],
    [+25.8%],
  ),
  caption: "慢诚实节点数扫频下的吞吐量与复用增益（b=1024, N=12, 额外延迟=150ms）",
  label-name: "tbl_slow_count_sweep",
)

数据在慢节点数 $= 4$ 处出现明显跳变，原因在于 $N=12$、$f=3$ 配置下 ACS 每轮需收集 $n-f=9$ 个 PRBC 完成信号。慢节点数 $<= 3$ 时，系统仍有 9 个以上的快速诚实节点，ACS 可以完全绕过所有慢节点直接推进共识。此时慢节点的迟到提案虽会被 Grace 窗口截留，但 ACS 每轮恰好从 9 个最快者中选取提案，复用池的引用与去重开销无处消化，复用增益为 $-6.9%$ 至 $+1.1%$。

当慢节点数增至 4 时，快速诚实节点降至 8 个，ACS 被迫等待至少 1 个 150 ms 慢节点，绝对吞吐从 43,408 TPS 骤降至 9,187 TPS（$-78.8%$）。与此同时，每轮至多 $f=3$ 个诚实提案因时序落后被排除在决策集合之外，Grace 窗口从"无物可收"转为"每轮回收至多 3 个迟到提案"，复用增益在同一边界点跳升至 $+30.0%$，为全部传输扰动实验中的最高值。此后慢节点数继续增加，复用增益稳定在约 $+25.8%$，但绝对吞吐持续恶化。

三类扰动实验共同指向同一结论：复用增益与"广播浪费的总量"正相关，与"ACS 能否绕过慢节点"强相关。全面均匀的延迟制造最多 $f$ 个迟到候选，复用增益约 $+24%$；稀疏慢节点（数量 $<= f$）产生的迟到提案被 ACS 自然跳过，复用几乎无从发力；当慢节点数量突破 ACS 可绕过的上限时，系统吞吐崩塌，而复用的回收条件恰在此时最为丰富。

== 拜占庭节点模拟

为评估复用机制在存在恶意节点时的鲁棒性，本文测试了两类拜占庭行为：静默节点（Silent Node）和无效回取响应（Invalid Fetch Response）。实验配置为 $N=12$、$b=4096$、$f=1$（单拜占庭节点），运行 8 轮共识，结果如 @tbl_byzantine 所示。

#thesis-table(
  columns: (1fr, 0.9fr, 0.9fr, 0.8fr),
  header: ([拜占庭行为], [`reuse_off` TPS], [`reuse_on` TPS], [复用增益]),
  rows: (
    [静默节点],
    [106,972],
    [128,375],
    [+20.0%],
    [无效 Fetch],
    [117,035],
    [135,582],
    [+15.9%],
  ),
  caption: "单拜占庭节点场景下 FIN 后端的吞吐量（b=4096, N=12）",
  label-name: "tbl_byzantine",
)

两类拜占庭行为下的复用增益（$+15.9%$ 至 $+20.0%$）均与干净网络下的水平（$+23.3%$ at $b=4096$）基本一致，表明单点恶意行为未能实质性削弱复用机制的回收效率。

两类场景的绝对吞吐量差异值得关注：无效 Fetch 场景（复用开启时 135,582 TPS）反而高于静默节点场景（128,375 TPS）。无效 Fetch 场景中，拜占庭节点仍正常参与 ACS 共识和提案广播，仅在被要求提供缺失数据时返回损坏响应；而静默节点完全不提供提案，使 ACS 每轮可用的诚实提案池缩小，总交付量随之下降。这一差异说明，"提案参与度"对吞吐量的影响比"数据完整性攻击"更为直接——前者减少了 ACS 的输入规模，后者仅增加了 Fetch 路径的重试成本。

== 截留窗口敏感性测试

本节分析 Grace 截留窗口时长对复用收益的影响。理想网络下的完整吞吐量随截留窗口时长变化数据（0 ms 至 800 ms，波动在 $plus.minus 4%$ 以内）见附录 @tbl_grace_sensitivity_clean；正文聚焦更能体现 Grace 窗口价值的边界故障条件。

实验设置 $f=3$（$N=12$ 的容错上限），包含 2 个慢诚实节点（pid 9, 10，额外延迟 150 ms）和 1 个静默拜占庭节点（pid 11），将诚实节点池恰好压缩至 ACS 所需的下限 $n-f=9$。对照组为仅含 2 个慢诚实节点（无拜占庭）的场景，结果如 @tbl_grace_faulty 所示。

#thesis-table(
  columns: (0.8fr, 1fr, 1fr, 1fr, 1fr),
  header: ([`grace_ms`], [2慢 `off`], [2慢 `on`], [2慢+1静默 `off`], [2慢+1静默 `on`]),
  rows: (
    [0],
    [122,328],
    [125,545],
    [126,090],
    [126,701],
    [50],
    [123,253],
    [126,690],
    [122,508],
    [126,238],
    [100],
    [124,179],
    [121,337],
    [117,442],
    [126,498],
    [200],
    [127,456],
    [116,894],
    [114,863],
    [120,326],
    [400],
    [124,162],
    [120,146],
    [108,427],
    [106,239],
    [800],
    [113,963],
    [114,526],
    [113,930],
    [125,789],
  ),
  caption: "f=3 边界故障条件下 Grace 窗口的TPS_wall（b=4096, N=12）",
  label-name: "tbl_grace_faulty",
)

仅含 2 个慢诚实节点时，系统仍有 10 个快速诚实节点，ACS 选取前 9 个完成者即可推进，150 ms 慢节点始终赶不上决策节奏。Grace 窗口的长短无法改变这一基本时序关系，增益贡献有限（最高 $+2.8%$ at $g=50$）。

引入第 3 个故障节点（静默拜占庭）后，诚实节点池降至恰好 9 个，ACS 须等待全部 2 个慢节点完成 PRBC 方能凑齐提案。此时，Grace 窗口开始产生可观测的收益：当 $g=800$ ms 时，复用开启下的吞吐量（125,789 TPS）比复用关闭高出 $+10.4%$；而在 2 慢无拜占庭的对照组，同一窗口长度下两种配置已无明显差距。

拜占庭节点的直接影响也体现在绝对吞吐量上：2 慢诚实场景的复用关闭平均 TPS（~122.5K）高于 2 慢+1 静默场景（~117.2K），静默节点减少了 ACS 的有效提案数，这一损失在复用关闭配置下无法补偿。复用开启配置则在两种场景下均表现出更强的稳定性（平均值 ~120.7K 与 ~122.0K 基本持平），部分弥补了拜占庭节点压缩诚实提案池所带来的损耗。

上述结果表明，Grace 截留窗口的参数选择与部署环境密切相关：在网络同质、节点健康的局域网环境中，短窗口已足够；当系统运行在接近容错极限、存在慢节点或拜占庭节点的场景下，适当延长 Grace 窗口能够有效回收因被迫等待而产生的时序落后广播，提供额外的吞吐保障。

== 实验结论与局限性说明

四组实验共同支持以下判断：跨轮次复用的增益与两个变量正相关——"各节点 PRBC 完成时序的分散程度"和"ACS 无法绕过慢节点的程度"。当两者同时成立时（如慢节点数突破 ACS 可跳过的上限，或全局均匀延迟使所有节点同等迟到），复用的回收价值最大，增益可达 $+24%$ 至 $+30%$；当 ACS 能够自然绕过慢节点时，迟到数据虽被截留，复用池的管理开销反而使增益收窄乃至转负。这一规律贯穿批处理规模扫频、节点规模扩展、传输扰动和拜占庭场景，具有一定的普适性。

`bytes/tx` 指标在 $b >= 16,384$ 后稳定于 148–155 bytes/tx（FIN 复用开启），表明此区间内复用引入的元数据开销已被充分稀释，协议的追踪通信成本接近不可再压缩的下界。

本研究存在以下局限。所有实验均基于本地多进程 QUIC 回环网络，缺乏真实广域网环境下的跨机器验证；WAN 中各节点间延迟的异质性与长尾效应可能进一步放大复用收益，也可能对 Fetch 路径的触发频率产生不可预知的影响。拜占庭攻击仅覆盖静默节点和无效回取响应两种基础行为，选择性静默、定时欺诈、多轮共谋等针对性策略尚未测试。节点规模受单机资源限制，仅测试至 $N=16$，$N >= 20$ 的表现有待后续研究。此外，追踪通信成本依赖驱动层应用数据包统计，未来应通过网卡级抓包（`tcpdump` 或 `eBPF`）获取更精确的物理网络层带宽数据。

= 总结与展望

// 约 1000 字

本文针对基于异步公共子集（ACS）的 BFT 共识协议中，因广播与共识阶段严格串行而导致“诚实但迟到”的广播数据被丢弃的问题，设计并实现了一种跨轮次广播复用机制。

在机制设计与工程实现方面，本课题在不修改底层 ACS 协议一致性内核的前提下，构建了一套完整的缓存复用流程。该机制通过引入有限时长的 Grace 窗口截留历史提案，采用“内联负载+引用”的统一提案编码，并结合复用池的生命周期管理以及异步回取 （Fetch） 机制，实现了对迟到广播成果的安全回收。

在系统评估方面，本文基于 Rust 语言开发了原型系统，并在 $n=12$ 的多进程仿真环境中完成了对比实验。结果表明，该机制在接入 Dumbo 与 FIN 两种主流 ACS 后端时，均能将端到端吞吐量稳定提升 10% 至 20%。该方案为现有的串行异步共识系统提供了一种低侵入、易落地的性能优化途径。

在研究过程中，本文观察到：广播浪费问题来源于于严格串行 ACS 结构对共识历史中偏序信息（Partial Order）的主动抛弃

近年来，学术界提出了一些完全并行的异步共识方案（如 Dumbo-NG 或基于 DAG 的 Narwhal and Tusk）。这些方案通过在协议底层维护多轮水位线或图结构等复杂的偏序关系，实现了广播与共识的完全解耦。在这种架构下，“迟到”的数据能被后续的偏序边直接引用，从根本上规避了带宽浪费问题。

不过，维护全局的偏序关系不可避免地会带来更高的系统状态复杂度和更复杂的元数据维护机制。相比之下，本文提出的跨轮复用机制，是在不引入复杂偏序逻辑的前提下，对经典串行 ACS 架构进行的一种局部性能补偿。能以较低的工程代价，对原本会被丢弃的广播成果进行回收。

在未来的研究工作中，可以考虑将该机制在真实的广域网环境中进行部署测试，进一步评估其在高延迟波动下的性能表现；同时，也需要结合区块链系统在真实部署中的安全威胁、资源约束与工程实现复杂度开展更系统的验证 @HanXuanQuKuaiLianAnQuanWenTiYanJiuXianZhuangYuZhanWang2019。
