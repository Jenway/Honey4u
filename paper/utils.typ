// utils.typ
#import "@preview/cuti:0.3.0": fakebold
#import "fonts.typ": *

// 内部辅助函数
#let chapter-number() = {
  counter(heading.where(level: 1)).get().at(0, default: 0)
}

#let centered-page-number(pattern: "1") = context [
  #set align(center)
  #set text(font: en, size: 9pt)
  #counter(page).display(pattern)
]

#let centered-page-number-fullwidth-roman = context {
  let n = counter(page).get().first()
  let chars = (
    "M", "Ⅿ", "D", "Ⅾ", "C", "Ⅽ", "L", "Ⅼ", "X", "Ⅹ", "V", "Ⅴ", "I", "Ⅰ",
  )
  let roman = numbering("I", n)
  let result = ""
  for c in roman {
    let found = false
    for (latin, fullwidth) in (
      ("M", "Ⅿ"), ("D", "Ⅾ"), ("C", "Ⅽ"), ("L", "Ⅼ"),
      ("X", "Ⅹ"), ("V", "Ⅴ"), ("I", "Ⅰ"),
    ) {
      if c == latin {
        result += fullwidth
        found = true
        break
      }
    }
    if not found { result += c }
  }
  set align(center)
  set text(font: en, size: 9pt)
  result
}

#let front-title(body) = {
  v(0.8em)
  align(center)[
    #set text(font: (..hei,), size: 18pt, weight: "bold")
    #fakebold[#body]
  ]
  v(0.5em)
}

#let distr(s, w: 4em) = {
  block(
    width: w,
    stack(
      dir: ltr,
      ..s.clusters().map(x => text(x)).intersperse(1fr),
    ),
  )
}

// 供用户调用的组件
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

#let thesis-table(columns: (), header: (), rows: (), caption: "", label-name: "") = {
  let new-label = if label-name != "" { label(label-name) } else { none }
  set figure.caption(position: top)
  [
    #figure(
      supplement: [表],
      caption: caption,
      kind: table,
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
    )#(if label-name != "" { new-label } else { [] })
  ]
}

#let algox(body, caption: "", label-name: "algox-ref") = {
  figure(
    kind: "code",
    supplement: [代码],
    caption: none,
  )[
    #context {
      table(
        columns: 1fr,
        align: (left,),
        stroke: none,
        table.header(
          table.cell(
            colspan: 1,
            [
              #set align(center)
              #set text(font: (..hei,), size: 10.5pt, weight: "bold")
              #line(start: (-5pt, 0pt), length: 100% + 10pt, stroke: 0.5pt)
              #v(-0.5em)
              #text(font: (..hei,), size: 10.5pt, weight: "bold", fill: rgb("C00000"))[#ref(label(label-name))#h(1em)]
              #caption
            ],
          ),
          table.hline(stroke: 0.5pt),
        ),
        body,
        table.hline(stroke: 0.5pt),
      )
    }
  ]
}
}
