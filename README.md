# Honey4u

毕业设计：面向基于异步公共子集（ACS）的异步 BFT 共识协议的广播数据跨轮次复用机制。

## What is this

`honey-crypto` 实现了一些密码学原语，如基于 BLST 的门限加密之类。

`honey-acs` 给出了 FIN（Modified）、HoneyBadger 及 Dumbo 协议的实现。

`honey-node`、`honey-transport` 是原型系统的外部驱动层及复用机制的实现。

`honey-bench` 用来跑实验之类的。

`paper` 包含自用的 typst 论文模板（不保证完全符合规范）及论文内容。

## How to run this

```bash
uv sync --dev --locked
cargo build -p honey-node --release --features quic
cargo run -p honey-bench -- \
  --node-binary target/release/honey-node.exe \
  --suite-config configs/paper/core/paper_highload.toml \
  --experiments highload_base
```

`cargo` 命令可能需要在 `venv` 环境中运行。

## Others

Python 实现的 Dumbo(CCS’20) ACS 来源于原论文 [yylluu/dumbo](https://github.com/yylluu/dumbo) 的实现，做了比较大幅度的修改。

FIN(CCS’23)　的实现参考了　[JUMBO](https://github.com/tca-sp/jumbo)　的　golang 实现。

这个代码库使用了 LLM 生成的代码。

名字的来源：这是第四次推倒重写。或者可以是 "Honey for you"；我想这算是个比较 fancy 的名字。

[fascy](https://github.com/fascy) 提供了许多指导与帮助。譬如说，这个毕设题目实际上就来自 [Dumbo_NG](https://github.com/fascy/Dumbo_NG) ，只不过最后貌似没有具体实现（因为并行 ACS 不会有迟到广播数据带宽浪费问题）。
