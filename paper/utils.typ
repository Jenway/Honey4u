// utils.typ
#import "@preview/cuti:0.3.0": fakebold
#import "fonts.typ": *

// ─── Internal helpers ──────────────────────────────────────────────────────

#let chapter-number() = {
  counter(heading.where(level: 1)).get().at(0, default: 0)
}

#let centered-page-number(pattern: "1") = context [
  #set align(center)
  #set text(font: en, size: fontsize.小五)
  #counter(page).display(pattern)
]

#let centered-page-number-fullwidth-roman = context {
  let n = counter(page).get().first()
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
  set text(font: en, size: fontsize.小五)
  result
}

#let front-title(body) = {
  v(0.8em)
  align(center)[
    #set text(font: 黑体, size: fontsize.小二, weight: "bold")
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

// ─── User-facing components ────────────────────────────────────────────────

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
        table.hline(y: 0, stroke: 1.5pt),
        table.hline(y: 1, stroke: 0.75pt),
        table.header(..header),
        ..rows,
        table.hline(y: auto, stroke: 1.5pt),
      ),
    )#(if label-name != "" { new-label } else { [] })
  ]
}

#let algox(..lines, caption: "", label-name: "algox-ref") = {
  let nxt = state("algox-" + label-name, false)
  [
    #let new-label = label(label-name)
    #figure(kind: "code", supplement: [代码], [])#new-label
    #v(-1.25em)

    #table(
      columns: 1fr,
      align: (left,),
      stroke: none,
      table.header(
        table.cell(
          colspan: 1,
          {
            context if nxt.get() {
              set align(center)
              set text(font: 黑体, size: fontsize.五号, weight: "bold", fill: rgb("C00000"))
              [续#ref(new-label) ]
              set text(fill: black)
              caption
              nxt.update(false)
            } else {
              set align(center)
              set text(font: 黑体, size: fontsize.五号, weight: "bold")
              line(start: (-5pt, 0pt), length: 100% + 10pt, stroke: 0.5pt)
              v(-0.5em)
              text(font: 黑体, size: fontsize.五号, weight: "bold", fill: rgb("C00000"))[#ref(new-label)#h(1em)]
              caption
              nxt.update(true)
            }
          },
        ),
        table.hline(stroke: 0.5pt),
      ),
      ..lines.pos(),
      table.hline(stroke: 0.5pt),
    )
  ]
}
