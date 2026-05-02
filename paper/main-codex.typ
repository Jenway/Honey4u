#import "sdu-thesis.typ": sdu-thesis, thesis-table

#show: sdu-thesis.with(
  title: "面向异步公共子集协议的广播数据跨轮次复用机制研究与实现",
  english_title: "Research and Implementation of Cross-Round Broadcast Reuse for ACS-Based Asynchronous BFT",
  author: "待填写",
  school_id: "待填写",
  school: "计算机科学与技术学院",
  major: "计算机科学与技术",
  grade: "待填写",
  supervisor: "待填写",
  date: "2026年5月",

  abstract_zh: [
    面向异步公共子集（Asynchronous Common Subset, ACS）的拜占庭容错共识协议通常采用“广播保证可用性 + 一致性选择公共子集”的两阶段结构。该结构简单而稳健，但也会产生一个容易被忽视的工程问题：一轮协议只需接纳不少于 $N-f$ 个提案即可推进，因此部分诚实但延迟到达的广播结果即使已经完成传播，也可能因时序落后而被当前轮丢弃，从而造成广播开销浪费。针对这一问题，本文围绕 HoneyBadger 与 Dumbo 一类基于 ACS 的异步 BFT 协议，设计并实现了一种广播数据跨轮次复用机制。该机制以“已经完成可用性证明但未被本轮决定采用的广播输出”为复用对象，通过统一提案编码、证明绑定引用、有限生命周期缓存与缺失数据回取路径，使迟到但有效的广播结果能够在后续轮次中重新进入提案流程。

    实现方面，本文在 ACS 输入边界引入“内联负载 + 历史引用”的统一表示，并实现广播复用池、条目标识、失效回收和缺失数据回取路径，使迟到广播结果能够被后续轮次安全引用。实验在 $N=12, f=3$ 的本地多进程环境下展开，覆盖高负载、Grace 窗口敏感性、慢诚实节点以及最小边界故障场景。结果表明，跨轮次复用能够稳定提高端到端吞吐量，高负载 QUIC 主结果在 Dumbo 与 FIN 风格两条路径上都呈现持续的 `TPS_wall` 正增长。另一方面，按每笔已交付交易归一化后的追踪通信成本并未随之稳定下降，这说明吞吐恢复与通信开销改善在本文实现中并不必然同时出现。因此，本文把结论限定在较明确的范围内：跨轮次复用能够回收部分“诚实但迟到”的广播成果，并将其转化为后续轮次的吞吐收益；至于更强的广域网推广结论以及跨机器复现，还需要进一步实验支持。
  ],
  keywords_zh: ("异步拜占庭容错", "异步公共子集", "HoneyBadger", "Dumbo", "跨轮次复用"),

  abstract_en: [
    ACS-based asynchronous Byzantine fault-tolerant protocols are robust because they guarantee liveness without timing assumptions, yet their standard two-stage structure also creates an engineering inefficiency. Since a round can terminate once at least $N-f$ proposals are chosen, some honest but delayed broadcast outputs may complete dissemination and still be discarded by the current round. This thesis addresses that inefficiency with a cross-round broadcast reuse mechanism for ACS-based protocols in the HoneyBadger and Dumbo family.

    The mechanism reuses certified but unselected broadcast outputs through a unified proposal format with inline payloads and proof-carrying references, bounded local cache management, and an on-demand refetch path for missing payloads. Experiments in a local $N=12, f=3$ multi-process setting show consistent end-to-end throughput improvements for both the Dumbo path and the FIN-style path. At the same time, the tracked communication cost per delivered transaction does not decrease uniformly, which suggests that throughput recovery and communication-efficiency gains are not always reproduced together. The thesis therefore presents the conclusion conservatively: cross-round reuse is a practical outer-layer optimization for recovering delayed but valid broadcast outputs and converting them into later throughput gains, while broader claims about bandwidth reduction and deployment generality still require further evidence.
  ],
  keywords_en: ("asynchronous BFT", "ACS", "HoneyBadger", "Dumbo", "cross-round reuse"),

  bibliography_file: "refer.bib",

  acknowledgements: [
    在本课题的研究、实现与写作过程中，感谢指导教师在选题边界、协议背景、实现路线和论文组织方面所提供的持续指导。感谢 HoneyBadger、Dumbo、Dumbo-NG 等相关论文与开源实现的作者，为机制设计、代码实现和实验复现提供了重要参考。感谢本地实验环境为系统测试、数据整理与论文撰写提供的支持。
  ],

  appendix: [],
)
