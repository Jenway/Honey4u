// layouts/frontmatter.typ
#import "../fonts.typ": *
#import "../utils.typ": front-title, fakebold

#let render-zh-abstract(info) = {
  front-title([摘#h(2em)要])
  set text(font: (..song, en), size: 12pt)
  set par(first-line-indent: (amount: 2em, all: true), leading: 6pt, justify: true)
  info.abstract_zh
  v(1em)
  set par(first-line-indent: 0em)
  text(font: (..hei,), size: 12pt, weight: "bold")[关键字]
  h(0.5em)
  text(font: (..song,), size: 12pt)[#info.keywords_zh.join("；")]
}

#let render-en-abstract(info) = {
  front-title([ABSTRACT])
  set text(font: (en, ..song), size: 12pt)
  set par(first-line-indent: (amount: 2em, all: true), leading: 6pt, justify: true)
  info.abstract_en
  v(1em)
  set par(first-line-indent: 0em)
  text(font: en, size: 12pt, weight: "bold")[Key Words]
  h(0.5em)
  text(font: en, size: 12pt)[#info.keywords_en.join(", ")]
}
