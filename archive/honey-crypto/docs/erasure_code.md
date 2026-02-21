# Erasure Code

这是基于 Reed–Solomon 的 systematic 纠删码实现，底层使用 ISA-L 提供的 GF(2^8) 运算与矩阵编码接口。

纠删码提供了这样一个机制：

给定参数 k，n

将消息经过纠删码处理后得到 n 个分片

只要有至少 k 个分片就可以恢复原消息
