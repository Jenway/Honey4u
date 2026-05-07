// layouts/cover.typ
#import "../fonts.typ": *
#import "../utils.typ": distr

#let cover-label(label-str) = {
  text(font: 楷体_GB2312, size: fontsize.三号, weight: "bold")[#distr(label-str)]
}

#let cover-value(value) = {
  align(center + horizon)[
    #box(
      width: 100%,
      stroke: (bottom: 0.5pt),
      inset: (bottom: 0.2em),
    )[
      #text(font: 宋体, size: fontsize.四号, weight: "regular")[#value]
    ]
  ]
}

#let render-cover(info) = {
  align(center)[
    #if info.cover_logo != none {
      v(1.5cm)
      box(
        width: 70%,
      )[
        #info.cover_logo
      ]
      v(1.3cm)
    }
    #scale(x: 76%, reflow: true)[
      #text(font: ((name: en, covers: "latin-in-cjk"), 黑体), size: 62pt, tracking: 0.2em)[毕业论文]
      #h(-0.1em) // 拉近括号
      #text(font: 楷体_GB2312, size: 62pt, tracking: 0.2em)[（]
      #h(-0.1em) // 拉近括号
      #text(font: ((name: en, covers: "latin-in-cjk"), 黑体), size: 62pt, tracking: 0.2em)[设计]
      #h(-0.1em) // 拉近括号
      #text(font: 楷体_GB2312, size: 62pt, tracking: 0.2em)[）]
    ]
    #v(0.6cm)

    #align(left)[
      #text(font: 宋体, size: fontsize.三号, weight: "bold")[论文（设计）题目：]
    ]

    #v(1.5cm)
    #text(font: 宋体, size: fontsize.小三, weight: "bold")[#info.title]
    #v(0.5fr)
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
    #text(font: 楷体, size: fontsize.四号, weight: "bold")[#info.date]
    #v(0.5cm)
  ]
}

#let render-score-sheet(info) = {
  if info.score_sheet == none {
    align(center)[
      #v(11cm)
      #text(font: 黑体, size: fontsize.小二, weight: "bold")[成绩评定表]
      #v(1cm)
      #text(font: 宋体, size: fontsize.小四)[To be filled]
    ]
  } else {
    info.score_sheet
  }
}
