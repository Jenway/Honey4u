// layouts/frontmatter.typ
#import "../fonts.typ": *
#import "../utils.typ": front-title, fakebold

#let render-zh-abstract(info) = {
  front-title([摘#h(2em)要])
  set text(font: (宋体, en), size: fontsize.小四, top-edge: "ascender", bottom-edge: "descender")
  set par(first-line-indent: (amount: 2em, all: true), leading: 23pt - 1em, spacing: 23pt - 1em, justify: true)
  info.abstract_zh
  v(1em)
  set par(first-line-indent: 0em)
  text(font: 黑体, size: fontsize.小四, weight: "bold")[关键词]
  h(0.5em)
  text(font: 宋体, size: fontsize.小四)[#info.keywords_zh.join("；")]
}

#let render-en-abstract(info) = {
  front-title([ABSTRACT])
  set text(font: (en, 宋体), size: fontsize.小四, top-edge: "ascender", bottom-edge: "descender")
  set par(first-line-indent: (amount: 2em, all: true), leading: 23pt - 1em, spacing: 23pt - 1em, justify: true)
  info.abstract_en
  v(1em)
  set par(first-line-indent: 0em)
  text(font: en, size: fontsize.小四, weight: "bold")[Key Words]
  h(0.5em)
  text(font: en, size: fontsize.小四)[#info.keywords_en.join(", ")]
}
