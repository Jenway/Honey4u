// lib.typ
#import "@preview/cuti:0.3.0": show-cn-fakebold
#import "fonts.typ": *
#import "utils.typ": *
#import "layouts/cover.typ": render-cover, render-score-sheet
#import "layouts/frontmatter.typ": render-en-abstract, render-zh-abstract
#import "layouts/backmatter.typ": *

#let sdu-thesis(
  title: "",
  author: "",
  school_id: "",
  school: "计算机科学与技术学院",
  major: "",
  grade: "",
  supervisor: "",
  date: "",
  cover_logo: none,
  abstract_zh: [],
  keywords_zh: (),
  abstract_en: [],
  keywords_en: (),
  score_sheet: none,
  references: none,
  bibliography_file: "refer.bib",
  bibliography_style: "gb-7714-2015-numeric",
  acknowledgements: none,
  appendix: none,
  translation_zh: none,
  translation_en: none,
  back_cover: none,
  body,
) = {
  // 1. 在 root 层级预解析路径，避免子组件内路径偏移
  let cover_logo_content = if cover_logo != none {
    image(cover_logo, width: 80%)
  } else {
    none
  }

  let bibliography_content = if bibliography_file != none {
    if bibliography_style == none {
      bibliography(bibliography_file, title: none)
    } else {
      bibliography(bibliography_file, title: none, style: bibliography_style)
    }
  } else {
    none
  }

  // 2. 包装上下文信息，方便传递给子模块
  let info = (
    title: title,
    author: author,
    school_id: school_id,
    school: school,
    major: major,
    grade: grade,
    supervisor: supervisor,
    date: date,
    cover_logo: cover_logo_content,
    abstract_zh: abstract_zh,
    keywords_zh: keywords_zh,
    abstract_en: abstract_en,
    keywords_en: keywords_en,
    score_sheet: score_sheet,
    references: references,
    bibliography_content: bibliography_content,
    acknowledgements: acknowledgements,
    appendix: appendix,
    translation_zh: translation_zh,
    translation_en: translation_en,
  )

  // 2. 全局基础页面与段落配置
  set page(paper: "a4", margin: (top: 2.5cm, bottom: 2.5cm, left: 3cm, right: 3cm))
  set outline(depth: 3, indent: 2em)
  set figure(numbering: n => context numbering("1-1", chapter-number(), n))
  set math.equation(numbering: n => context numbering("(1-1)", chapter-number(), n))
  show figure.where(kind: table): set figure.caption(position: top)

  show: show-cn-fakebold

  // 3. 开始排版：封面与成绩单 (无页眉页脚)
  render-cover(info)
  pagebreak()

  render-score-sheet(info)
  pagebreak()

  // 4. 前置内容 (摘要)
  set page(header: [], footer: [])
  render-zh-abstract(info)
  pagebreak()
  render-en-abstract(info)

  // 5. 目录 (罗马数字页码)
  set page(header: [], footer: centered-page-number-fullwidth-roman)
  counter(page).update(1)
  front-title([目#h(2em)录])
  set text(font: (..song,), size: 12pt)
  set par(first-line-indent: 0em, justify: false)
  outline(title: none)

  // 6. 正文 (阿拉伯数字页码，带页眉)
  let body-header = context [
    #set align(center)
    #set text(font: (..song,), size: 9pt)
    山东大学本科毕业论文（设计）
    #v(-0.55em)
    #line(length: 100%, stroke: 0.5pt)
  ]
  set page(header: body-header, footer: centered-page-number(pattern: "1"))
  counter(page).update(1)

  // 正文样式设定
  set text(font: (..song, en), size: 12pt)
  set par(first-line-indent: (amount: 2em, all: true), leading: 6pt, justify: true)
  set heading(numbering: "1.1")

  let heading-is-cjk(body) = {
    let s = repr(body)
    for c in s.clusters() {
      let ch = c.codepoints().first()
      if ch >= "\u{4E00}" and ch <= "\u{9FFF}" {
        return true
      }
    }
    false
  }

  show heading.where(level: 1): it => {
    pagebreak(weak: true)
    v(14.4pt)
    align(center)[
      #set text(font: (..hei,), size: if heading-is-cjk(it.body) { 16pt } else { 15pt }, weight: "bold")
      #it
    ]
    v(9pt)
  }

  show heading.where(level: 2): it => {
    v(9pt)
    set text(font: (..hei,), size: if heading-is-cjk(it.body) { 14pt } else { 14pt }, weight: "bold")
    it
    v(9pt)
  }

  show heading.where(level: 3): it => {
    set text(font: (..hei,), size: if heading-is-cjk(it.body) { 12pt } else { 13pt }, weight: "bold")
    it
    v(0.35em)
  }

  show figure.caption: it => block(width: 100%)[
    #set align(center)
    #set text(font: (..song,), size: 10.5pt, weight: "bold")
    #it.supplement
    #context it.counter.display(it.numbering)
    #h(0.6em)
    #it.body
  ]

  // 渲染正文内容
  body

  // 7. 后置内容排版
  {
    show heading.where(level: 1): it => {
      v(0.8em)
      align(center)[
        #set text(font: (..hei,), size: 18pt, weight: "bold")
        #it
      ]
      v(0.5em)
    }
    render-references(info)
  }

  if info.acknowledgements != none {
    show heading.where(level: 1): it => {
      v(0.8em)
      align(center)[
        #set text(font: (..hei,), size: 18pt, weight: "bold")
        #it
      ]
      v(0.5em)
    }
    render-acknowledgements(info)
  }

  if info.appendix != none {
    show heading.where(level: 1): it => {
      v(0.8em)
      align(center)[
        #set text(font: (..hei,), size: 18pt, weight: "bold")
        #it
      ]
      v(0.5em)
    }
    render-appendix(info)
  }

  if info.translation_zh != none {
    show heading.where(level: 1): it => {
      v(0.8em)
      align(center)[
        #set text(font: (..hei,), size: 18pt, weight: "bold")
        #it
      ]
      v(0.5em)
    }
    set page(header: [], footer: [])
    render-translation-zh(info)
  }

  if info.translation_en != none {
    show heading.where(level: 1): it => {
      v(0.8em)
      align(center)[
        #set text(font: (..hei,), size: 18pt, weight: "bold")
        #it
      ]
      v(0.5em)
    }
    set page(header: [], footer: [])
    render-translation-en(info)
  }

  if back_cover != none {
    set page(header: [], footer: [])
    back_cover
  }
}
