// layouts/cover.typ
#import "../fonts.typ": *
#import "../utils.typ": distr

#let cover-label(label-str) = {
  text(font: kai_gb2312, size: 16pt, weight: "bold")[#distr(label-str)]
}

#let cover-value(value) = {
  align(center + horizon)[
    #box(
      width: 100%,
      stroke: (bottom: 0.5pt),
      inset: (bottom: 0.2em),
    )[
      #text(font: (..song,), size: 14pt, weight: "regular")[#value]
    ]
  ]
}

#let render-cover(info) = {
  align(center)[
    #if info.cover_logo != none {
      info.cover_logo
      v(1.5cm)
    }
    #scale(x: 68%, reflow: true)[
      #text(
        font: ((name: en, covers: "latin-in-cjk"), ..hei),
        size: 66pt,
        tracking: 0.2em,
      )[毕业论文（设计）]
    ]
    #v(1.5cm)
    #text(font: (..hei,), size: 18pt, weight: "bold")[论文（设计）题目：#info.title]
    #v(1fr)
    #box(width: 280pt)[
      #grid(
        columns: (auto, 1fr),
        row-gutter: 1.5em,
        column-gutter: 1em,
        align: (left + horizon, center + horizon),
        cover-label("姓名"), cover-value(info.author),
        cover-label("学号"), cover-value(info.school_id),
        cover-label("学院"), cover-value(info.school),
        cover-label("年级"), cover-value(info.grade),
        cover-label("专业"), cover-value(info.major),
        cover-label("指导老师"), cover-value(info.supervisor),
      )
    ]
    #v(1fr)
    #text(font: (..kai,), size: 14pt, weight: "bold")[#info.date]
    #v(0.5cm)
  ]
}

#let render-score-sheet(info) = {
  if info.score_sheet == none {
    align(center)[
      #v(11cm)
      #text(font: (..hei,), size: 18pt, weight: "bold")[成绩评定表]
      #v(1cm)
      #text(font: (..song,), size: 12pt)[To be filled]
    ]
  } else {
    info.score_sheet
  }
}
