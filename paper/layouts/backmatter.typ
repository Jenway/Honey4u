// layouts/backmatter.typ
#import "../fonts.typ": *

#let section-text(body) = {
  set text(font: (..song, en), size: 12pt)
  set par(first-line-indent: (amount: 2em, all: true), leading: 6pt, justify: true)
  body
}

#let render-references(info) = {
  heading(level: 1, numbering: none)[参考文献]
  set text(font: (..song, en), size: 10.5pt)
  set par(first-line-indent: 0em, leading: 0.3em, justify: false)

  if info.bibliography_content != none {
    info.bibliography_content
  } else {
    if info.references == none {
      [[1] 请在模板参数中提供 `references` 内容，或传入 `bibliography_file`。]
    } else {
      info.references
    }
  }
}

#let render-acknowledgements(info) = {
  heading(level: 1, numbering: none)[致#h(2em)谢]
  section-text(info.acknowledgements)
}

#let render-appendix(info) = {
  heading(level: 1, numbering: none)[附#h(2em)录]
  section-text(info.appendix)
}

#let render-translation-zh(info) = {
  heading(level: 1, numbering: none)[译#h(2em)文]
  section-text(info.translation_zh)
}

#let render-translation-en(info) = {
  heading(level: 1, numbering: none)[外文原文]
  set text(font: (en, ..song), size: 12pt)
  set par(first-line-indent: (amount: 2em, all: true), leading: 6pt, justify: true)
  info.translation_en
}
