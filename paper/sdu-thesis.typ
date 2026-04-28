#let sdu-thesis(
  title: "",
  english_title: "",
  paper_type: "毕业论文（设计）",
  author: "",
  school_id: "",
  school: "计算机科学与技术学院",
  major: "",
  grade: "",
  supervisor: "",
  date: "",
  cover_logo: "assets/SDUWords.pdf",
  abstract_zh: [],
  keywords_zh: (),
  abstract_en: [],
  keywords_en: (),
  score_sheet: none,
  references: none,
  bibliography_file: none,
  bibliography_style: none,
  acknowledgements: none,
  appendix: none,
  translation_zh: none,
  translation_en: none,
  back_cover: none,
  body,
) = {
  let 宋体 = ("SimSun", "Noto Serif CJK SC", "Source Han Serif SC")
  let 黑体 = ("SimHei", "Noto Sans CJK SC", "Source Han Sans SC")
  let 西文字体 = "Times New Roman"

  let centered-page-number(pattern: "1") = context [
    #set align(center)
    #set text(font: 西文字体, size: 9pt)
    #counter(page).display(pattern)
  ]

  let chapter-number() = {
    counter(heading.where(level: 1)).get().at(0, default: 0)
  }

  let body-header = context [
    #set align(center)
    #set text(font: (..宋体), size: 9pt)
    山东大学本科毕业论文（设计）
    #v(-0.55em)
    #line(length: 100%, stroke: 0.5pt)
  ]

  let front-title(body) = {
    v(0.8em)
    align(center)[
      #set text(font: (..黑体), size: 18pt, weight: "bold")
      #body
    ]
    v(0.5em)
  }

  let body-text() = {
    set text(font: (..宋体, 西文字体), size: 12pt)
    set par(
      first-line-indent: 2em,
      leading: 6pt,
      justify: true,
    )
  }

  let abstract-text() = {
    set text(font: (..宋体, 西文字体), size: 12pt)
    set par(
      first-line-indent: 2em,
      leading: 6pt,
      justify: true,
    )
  }

  let reference-text() = {
    set text(font: (..宋体, 西文字体), size: 10.5pt)
    set par(
      first-line-indent: 0em,
      leading: 0pt,
      justify: false,
    )
  }

  let section-text(body) = {
    body-text()
    body
  }

  let cover-value(value) = block(
    width: 100%,
    inset: (x: 0.15cm, top: 0.05cm, bottom: 0.08cm),
    stroke: (bottom: 0.5pt),
  )[
    #text(font: (..宋体), size: 14pt)[#value]
  ]

  let render-score-sheet() = {
    if score_sheet == none {
      align(center)[
        #v(11cm)
        #text(font: (..黑体), size: 18pt, weight: "bold")[成绩评定表]
        #v(1cm)
        #text(font: (..宋体), size: 12pt)[To be filled]
      ]
    } else {
      score_sheet
    }
  }

  let render-cover() = {
    align(center)[
      #if cover_logo != none {
        image(cover_logo, width: 8.8cm)
        v(1.1cm)
      }
      #text(font: (..黑体), size: 22pt, weight: "bold")[山东大学本科#paper_type]
      #v(2.1cm)
      #text(font: (..黑体), size: 18pt, weight: "bold")[#title]
      #if english_title != "" {
        v(0.8cm)
        text(font: 西文字体, size: 16pt, weight: "bold")[#english_title]
      }
      #v(1cm)
      #grid(
        columns: (3.2cm, 8.6cm),
        column-gutter: 0.4cm,
        row-gutter: 0.9cm,
        align: (right, left),
        [#text(font: (..宋体), size: 14pt)[姓名]], [#cover-value(author)],
        [#text(font: (..宋体), size: 14pt)[学号]], [#cover-value(school_id)],
        [#text(font: (..宋体), size: 14pt)[学院]], [#cover-value(school)],
        [#text(font: (..宋体), size: 14pt)[专业]], [#cover-value(major)],
        [#text(font: (..宋体), size: 14pt)[年级]], [#cover-value(grade)],
        [#text(font: (..宋体), size: 14pt)[指导教师]], [#cover-value(supervisor)],
      )
      #v(2cm)
      #text(font: (..宋体), size: 14pt)[#date]
    ]
  }

  let render-zh-abstract() = {
    front-title([摘#h(2em)要])
    abstract-text()
    abstract_zh
    v(1em)
    set par(first-line-indent: 0em)
    text(font: (..黑体), size: 12pt, weight: "bold")[关键字]
    h(0.5em)
    text(font: (..宋体), size: 12pt)[#keywords_zh.join("；")]
  }

  let render-en-abstract() = {
    front-title([ABSTRACT])
    set text(font: (西文字体, ..宋体), size: 12pt)
    set par(
      first-line-indent: 2em,
      leading: 6pt,
      justify: true,
    )
    abstract_en
    v(1em)
    set par(first-line-indent: 0em)
    text(font: 西文字体, size: 12pt, weight: "bold")[Key Words]
    h(0.5em)
    text(font: 西文字体, size: 12pt)[#keywords_en.join(", ")]
  }

  let render-acknowledgements() = {
    front-title([致#h(2em)谢])
    section-text(acknowledgements)
  }

  let render-appendix() = {
    front-title([附#h(2em)录])
    section-text(appendix)
  }

  let render-translation-zh() = {
    front-title([译#h(2em)文])
    section-text(translation_zh)
  }

  let render-translation-en() = {
    front-title([外文原文])
    set text(font: (西文字体, ..宋体), size: 12pt)
    set par(
      first-line-indent: 2em,
      leading: 6pt,
      justify: true,
    )
    translation_en
  }

  let render-references() = {
    if bibliography_file != none {
      front-title([参考文献])
      reference-text()
      if bibliography_style == none {
        bibliography(bibliography_file, title: none)
      } else {
        bibliography(bibliography_file, title: none, style: bibliography_style)
      }
    } else {
      front-title([参考文献])
      reference-text()
      if references == none {
        [[1] 请在模板参数中提供 `references` 内容，或传入 `bibliography_file`。]
      } else {
        references
      }
    }
  }

  let render-back-cover() = {
    if back_cover != none {
      back_cover
    }
  }

  set page(
    paper: "a4",
    margin: (top: 2.5cm, bottom: 2.5cm, left: 3cm, right: 3cm),
  )

  set outline(depth: 3, indent: 2em)
  set figure(numbering: n => context numbering("1-1", chapter-number(), n))
  set math.equation(numbering: n => context numbering("(1-1)", chapter-number(), n))
  show figure.where(kind: table): set figure.caption(position: top)

  render-cover()
  pagebreak()

  render-score-sheet()
  pagebreak()

  set page(header: [], footer: [])
  render-zh-abstract()
  pagebreak()

  render-en-abstract()
  pagebreak()

  set page(header: [], footer: centered-page-number(pattern: "I"))
  counter(page).update(1)
  front-title([目#h(2em)录])
  set text(font: (..宋体), size: 12pt)
  set par(first-line-indent: 0em, justify: false)
  outline(title: none)
  pagebreak()

  set page(header: body-header, footer: centered-page-number(pattern: "1"))
  counter(page).update(1)

  body-text()
  set heading(numbering: "1.1")

  show heading.where(level: 1): it => {
    pagebreak(weak: true)
    v(0.8em)
    align(center)[
      #set text(font: (..黑体), size: 16pt, weight: "bold")
      #it
    ]
    v(0.5em)
  }

  show heading.where(level: 2): it => {
    v(0.5em)
    set text(font: (..黑体), size: 14pt, weight: "bold")
    it
    v(0.5em)
  }

  show heading.where(level: 3): it => {
    set text(font: (..黑体), size: 12pt, weight: "bold")
    it
    v(0.35em)
  }

  show figure.caption: it => block(width: 100%)[
    #set align(center)
    #set text(font: (..宋体), size: 10.5pt, weight: "bold")
    #it.supplement
    #context it.counter.display(it.numbering)
    #h(0.6em)
    #it.body
  ]

  body
  pagebreak()

  render-references()

  if acknowledgements != none {
    pagebreak()
    render-acknowledgements()
  }

  if appendix != none {
    pagebreak()
    render-appendix()
  }

  if translation_zh != none {
    pagebreak()
    set page(header: [], footer: [])
    render-translation-zh()
  }

  if translation_en != none {
    pagebreak()
    set page(header: [], footer: [])
    render-translation-en()
  }

  if back_cover != none {
    pagebreak()
    set page(header: [], footer: [])
    render-back-cover()
  }
}

#let codeblock(caption: "", body) = {
  figure(
    rect(width: 100%, stroke: 0.5pt, inset: 10pt, align(left, body)),
    caption: caption,
    kind: "code",
    supplement: [代码],
  )
}

#let thesis-figure(caption: "", body) = {
  figure(
    body,
    caption: caption,
    kind: image,
    supplement: [图],
  )
}

#let thesis-table(columns: (), header: (), rows: (), caption: "") = {
  figure(
    table(
      columns: columns,
      stroke: none,
      inset: (x: 0.35em, y: 0.3em),
      align: center + horizon,

      table.hline(y: 0, stroke: 0.8pt),
      table.hline(y: 1, stroke: 0.5pt),
      table.header(..header),
      ..rows,
      table.hline(y: auto, stroke: 0.8pt),
    ),
    caption: figure.caption(position: top, [#caption]),
    kind: table,
    supplement: [表],
  )
}
