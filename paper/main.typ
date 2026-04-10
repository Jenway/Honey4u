#import "sdu-thesis.typ": sdu-thesis, codeblock, thesis-table

#show: sdu-thesis.with(
  title: "基于 Typst 的山东大学本科毕业论文模板设计与实现",
  english_title: "Design and Implementation of a Typst Template for SDU Bachelor Thesis",
  author: "你的名字",
  school_id: "202100123456",
  school: "计算机科学与技术学院",
  major: "计算机科学与技术",
  grade: "2021级",
  supervisor: "指导教师名",
  date: "2026年4月",

  abstract_zh: [
    本文面向山东大学本科毕业论文（设计）撰写规范，设计并实现了一套基于 Typst
    的毕业论文模板。模板以学校正式通知中的结构顺序、页面设置、标题字号和参考文献
    规则为依据，对封面、摘要、目录、正文、参考文献、致谢、附录和译文等部分进行统
    一封装。实践表明，Typst 在保证版式一致性的同时，能够显著降低模板维护成本，提
    高论文撰写与迭代效率，为本科毕业论文的自动化排版提供了一种可行方案。
  ],
  keywords_zh: ("Typst", "山东大学", "本科毕业论文", "排版模板"),

  abstract_en: [
    This thesis develops a Typst-based template for Shandong University bachelor
    theses according to the official writing specification. The template covers the
    cover page, abstracts, table of contents, body text, references,
    acknowledgements, appendix, and translation sections in a unified way.
    The result shows that Typst can reduce template maintenance cost while keeping
    the document structure and typography stable.
  ],
  keywords_en: ("Typst", "Shandong University", "Bachelor Thesis", "Template"),

  score_sheet: [
    #align(center)[
      #v(11cm)
      #text(size: 18pt, weight: "bold")[成绩评定表]
      #v(1cm)
      #text(size: 12pt)[此页请替换为学院统一下发的成绩评定表 PDF 或扫描件。]
    ]
  ],

  bibliography_file: "references.bib",
  bibliography_style: "gb-7714-2015-numeric",

  acknowledgements: [
    感谢指导教师在选题、结构设计与规范核对方面给予的持续指导。感谢 Typst
    社区提供的文档、示例和工具链支持，使得论文模板的实现与迭代成为可能。
  ],

  appendix: [
    本附录用于放置不宜直接纳入正文的大段材料，例如接口定义、实验补充结果或长
    代码清单。若论文无需附录，可删除本段并在模板参数中移除 `appendix`。
  ],

  translation_zh: [
    本节用于放置与课题相关的外文资料中文译文。根据学校要求，译文一般应由指导教
    师指定，与论文研究主题紧密相关，并在中期检查前完成。
  ],

  translation_en: [
    This section can contain the original foreign-language material that matches the
    translated text. If the source file is already a PDF, it can be inserted here
    directly instead of copying the full text into Typst.
  ],
)

= 前言
== 研究背景
山东大学 2023 版本科毕业论文（设计）管理办法将撰写规范单列为附件，并对
封面、摘要、目录、页码和参考文献格式作出明确要求。相比依赖复杂宏包体系的
传统 LaTeX 模板，Typst 更适合将规则直接抽象为函数接口与样式约束 @sdu-rules-2023。

== 研究目标
本模板以“规范优先”为目标，重点保证以下几点：
- 文档结构顺序与学校要求一致
- 页眉页码分区符合正文与前置部分的差异
- 标题字号、段落格式与关键词样式统一
- 便于后续继续补足正式参考文献样式和学院专用附件

= 模板设计
== 结构设计
模板的核心思路是将封面、摘要、目录、正文、参考文献、致谢、附录和译文拆分为
独立渲染函数，由 `sdu-thesis` 在顶层统一调度。这样做可以避免正文作者直接修改
底层版式规则，提高模板复用性。模板写作和版式分离的思路，也与传统论文工具链
长期形成的实践一致 @liu-latex-2023。

== 编号与样式
图表和公式支持按章编号。例如公式 @eq-demo 用于展示模板中默认启用的章节编号
机制。

$ E = m c^2 $ <eq-demo>

== 代码环境
模板保留了代码块包装函数，便于在计算机类论文中插入程序清单。

#codeblock(caption: "Hello World in Typst")[
  ```typst
  #show "World": it => [Typst]
  Hello World
  ```
]

== 三线表示例
论文中常见的实验结果和参数对比更适合使用规范化三线表。下面给出模板内置表格环
境的一个简单示例 @wang-writing-2024。

#thesis-table(
  columns: (1.4fr, 1fr, 1fr),
  header: ([指标], [原始草稿], [当前模板]),
  rows: (
    [结构顺序], [不完整], [按规范重构],
    [页码分区], [全局阿拉伯数字], [前置罗马, 正文阿拉伯],
    [参考文献], [手写占位], [支持 bib 自动生成],
  ),
  caption: "模板改造前后对比",
)

= 结论
== 总结
当前版本已经按照学校正式通知重构了论文结构与主要页面规则，解决了原始 Typst
草稿中前置页顺序、页码分区和封面字段不完整的问题。

== 后续工作
后续仍需继续补强两个方向：其一是接入符合 GB/T 7714-2015 的 Typst 参考文献样
式；其二是根据具体学院要求替换成绩评定表和统一封面资产。
