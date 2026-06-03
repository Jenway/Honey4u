// utils.typ
#import "@preview/cuti:0.3.0": fakebold
#import "@preview/cetz:0.5.2"
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
      ("M", "Ⅿ"),
      ("D", "Ⅾ"),
      ("C", "Ⅽ"),
      ("L", "Ⅼ"),
      ("X", "Ⅹ"),
      ("V", "Ⅴ"),
      ("I", "Ⅰ"),
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

#let front-title-en(body) = {
  v(0.8em)
  align(center)[
    #text(font: en, size: fontsize.小二, weight: "bold")[#body]
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

#let thesis-figure(caption: "", label-name: "", body) = {
  let new-label = if label-name != "" { label(label-name) } else { none }
  [
    #figure(
      body,
      caption: caption,
      kind: image,
      supplement: [图],
      placement: none,
    )
    #(if label-name != "" { new-label } else { [] })
  ]
}

#let thesis-table(columns: (), header: (), rows: (), caption: "", label-name: "", header-rows: 1) = {
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
        table.hline(y: header-rows, stroke: 0.75pt),
        table.header(..header),
        ..rows,
        table.hline(y: auto, stroke: 1.5pt),
      ),
    )#(if label-name != "" { new-label } else { [] })
  ]
}

#let chart-panel(title: [], body) = block[
  #align(center)[
    #set text(font: 黑体, size: fontsize.五号, weight: "bold")
    #title
  ]
  #v(0.2em)
  #body
]

#let _chart-log2(v) = calc.log(v, base: 2)

#let _chart-scale-x-log(v, x-min, x-max, width) = {
  let minl = _chart-log2(x-min)
  let maxl = _chart-log2(x-max)
  (_chart-log2(v) - minl) / (maxl - minl) * width
}

#let _chart-scale-x-lin(v, x-min, x-max, width) = {
  (v - x-min) / (x-max - x-min) * width
}

#let _chart-scale-y(v, y-min, y-max, height) = {
  (v - y-min) / (y-max - y-min) * height
}

#let _chart-plot(
  width: 6.2,
  height: 4.2,
  x-min: 0,
  x-max: 1,
  y-min: 0,
  y-max: 1,
  x-label: "",
  y-label: "",
  x-log: false,
  x-ticks: (),
  y-ticks: (),
  series: (),
  legend-anchor: "north-east",
) = {
  let plot-w = width
  let plot-h = height
  let x-map = if x-log {
    v => _chart-scale-x-log(v, x-min, x-max, plot-w)
  } else {
    v => _chart-scale-x-lin(v, x-min, x-max, plot-w)
  }
  let y-map = v => _chart-scale-y(v, y-min, y-max, plot-h)

  cetz.canvas({
    import cetz.draw: *

    let left = 0
    let bottom = 0
    let right = plot-w
    let top = plot-h

    rect((left, bottom), (right, top), stroke: 0.7pt + rgb("666666"))

    for (tick, label) in x-ticks {
      let x = x-map(tick)
      line((x, bottom), (x, top), stroke: 0.35pt + rgb("DDDDDD"))
      line((x, bottom), (x, bottom - 0.08), stroke: 0.6pt + black)
      content((x, bottom - 0.18), anchor: "north", text(font: ("Times New Roman", "SimSun"), size: 8pt)[#label])
    }

    for (tick, label) in y-ticks {
      let y = y-map(tick)
      line((left, y), (right, y), stroke: 0.35pt + rgb("DDDDDD"))
      line((left - 0.08, y), (left, y), stroke: 0.6pt + black)
      content((left - 0.14, y), anchor: "east", text(font: ("Times New Roman", "SimSun"), size: 8pt)[#label])
    }

    content((plot-w / 2, bottom - 0.55), anchor: "north", text(
      font: ("Times New Roman", "SimSun"),
      size: 9pt,
    )[#x-label])
    content((left - 0.85, plot-h / 2), angle: 90deg, anchor: "south", text(
      font: ("Times New Roman", "SimSun"),
      size: 9pt,
    )[#y-label])

    for entry in series {
      let pts = entry.at("data").map(((x, y)) => (x-map(x), y-map(y)))
      line(..pts, stroke: entry.at("stroke"))
      for pt in pts {
        circle(pt, radius: 0.05, fill: entry.at("color"), stroke: entry.at("color"))
      }
    }

    let legend-x = if legend-anchor == "north-west" { 0.35 } else { plot-w - 1.55 }
    let legend-anchor-pos = if legend-anchor == "north-west" { "north-west" } else { "north-east" }
    let legend-box-a = if legend-anchor == "north-west" { (0.18, plot-h - 0.2) } else { (plot-w - 1.72, plot-h - 0.2) }
    let legend-box-b = if legend-anchor == "north-west" { (1.85, plot-h - 0.98) } else {
      (plot-w - 0.18, plot-h - 0.98)
    }
    rect(legend-box-a, legend-box-b, fill: white, stroke: 0.5pt + rgb("999999"))
    for (idx, entry) in series.enumerate() {
      let y = plot-h - 0.38 - idx * 0.28
      line((legend-x, y), (legend-x + 0.28, y), stroke: entry.at("stroke"))
      circle((legend-x + 0.14, y), radius: 0.04, fill: entry.at("color"), stroke: entry.at("color"))
      content((legend-x + 0.38, y), anchor: "west", text(font: ("Times New Roman", "SimSun"), size: 8pt)[#entry.at(
        "label",
      )])
    }
  })
}

#let highload-tps-chart() = [
  #align(center)[
    #stack(
      dir: ltr,
      spacing: 0.8em,
      chart-panel(title: [FIN 后端])[
        #_chart-plot(
          x-min: 32,
          x-max: 262144,
          y-min: 0,
          y-max: 180000,
          x-label: "批处理规模 b",
          y-label: "TPS_wall",
          x-log: true,
          x-ticks: (
            (32, [32]),
            (256, [256]),
            (2048, [2048]),
            (16384, [16384]),
            (131072, [131072]),
          ),
          y-ticks: (
            (0, [0]),
            (50000, [50k]),
            (100000, [100k]),
            (150000, [150k]),
          ),
          legend-anchor: "north-west",
          series: (
            (
              label: [开启复用],
              color: rgb("2E6F40"),
              stroke: 1.4pt + rgb("2E6F40"),
              data: (
                (32, 343),
                (64, 687),
                (128, 1370),
                (256, 2735),
                (512, 5436),
                (1024, 10695),
                (2048, 20801),
                (4096, 39263),
                (8192, 68854),
                (16384, 108320),
                (24576, 107927),
                (32768, 125082),
                (65536, 165708),
                (98304, 176139),
                (131072, 170837),
                (196608, 123646),
                (262144, 100008),
              ),
            ),
            (
              label: [关闭复用],
              color: rgb("666666"),
              stroke: 1.4pt + rgb("666666"),
              data: (
                (32, 276),
                (64, 551),
                (128, 1109),
                (256, 2206),
                (512, 4403),
                (1024, 8720),
                (2048, 16836),
                (4096, 31845),
                (8192, 56122),
                (16384, 88840),
                (24576, 90178),
                (32768, 104015),
                (65536, 129557),
                (98304, 157713),
                (131072, 128824),
                (196608, 124474),
                (262144, 86256),
              ),
            ),
          ),
        )
      ],
      chart-panel(title: [Dumbo 后端])[
        #_chart-plot(
          x-min: 32,
          x-max: 131072,
          y-min: 0,
          y-max: 160000,
          x-label: "批处理规模 b",
          y-label: "TPS_wall",
          x-log: true,
          x-ticks: (
            (32, [32]),
            (256, [256]),
            (2048, [2048]),
            (16384, [16384]),
            (131072, [131072]),
          ),
          y-ticks: (
            (0, [0]),
            (50000, [50k]),
            (100000, [100k]),
            (150000, [150k]),
          ),
          legend-anchor: "north-west",
          series: (
            (
              label: [开启复用],
              color: rgb("2E6F40"),
              stroke: 1.4pt + rgb("2E6F40"),
              data: (
                (32, 318),
                (64, 641),
                (128, 1257),
                (256, 2502),
                (512, 5021),
                (1024, 9980),
                (2048, 19189),
                (4096, 36380),
                (8192, 62803),
                (16384, 98729),
                (24576, 103974),
                (32768, 124658),
                (49152, 144337),
              ),
            ),
            (
              label: [关闭复用],
              color: rgb("666666"),
              stroke: 1.4pt + rgb("666666"),
              data: (
                (32, 255),
                (64, 506),
                (128, 1022),
                (256, 2038),
                (512, 4007),
                (1024, 7985),
                (2048, 15532),
                (4096, 29474),
                (8192, 52270),
                (16384, 83489),
                (24576, 87324),
                (32768, 103748),
                (49152, 124705),
                (131072, 159077),
              ),
            ),
          ),
        )
      ],
    )
  ]
]

#let slow-count-sweep-chart() = [
  #align(center)[
    #stack(
      dir: ltr,
      spacing: 0.8em,
      chart-panel(title: [绝对吞吐量])[
        #_chart-plot(
          x-min: 0,
          x-max: 8,
          y-min: 0,
          y-max: 50000,
          x-label: "慢诚实节点数",
          y-label: "TPS_wall",
          x-ticks: (
            (0, [0]),
            (1, [1]),
            (2, [2]),
            (3, [3]),
            (4, [4]),
            (8, [8]),
          ),
          y-ticks: (
            (0, [0]),
            (10000, [10k]),
            (20000, [20k]),
            (30000, [30k]),
            (40000, [40k]),
          ),
          legend-anchor: "north-east",
          series: (
            (
              label: [开启复用],
              color: rgb("2E6F40"),
              stroke: 1.4pt + rgb("2E6F40"),
              data: ((0, 42346), (1, 47209), (2, 40216), (3, 40392), (4, 11936), (8, 7046)),
            ),
            (
              label: [关闭复用],
              color: rgb("666666"),
              stroke: 1.4pt + rgb("666666"),
              data: ((0, 41903), (1, 43348), (2, 42850), (3, 43408), (4, 9187), (8, 5602)),
            ),
          ),
        )
      ],
      chart-panel(title: [复用增益])[
        #_chart-plot(
          x-min: 0,
          x-max: 8,
          y-min: -10,
          y-max: 30,
          x-label: "慢诚实节点数",
          y-label: "增益 (%)",
          x-ticks: (
            (0, [0]),
            (1, [1]),
            (2, [2]),
            (3, [3]),
            (4, [4]),
            (8, [8]),
          ),
          y-ticks: (
            (-10, [-10]),
            (0, [0]),
            (10, [10]),
            (20, [20]),
            (30, [30]),
          ),
          legend-anchor: "north-east",
          series: (
            (
              label: [零基线],
              color: rgb("BBBBBB"),
              stroke: 1pt + rgb("BBBBBB"),
              data: ((0, 0), (8, 0)),
            ),
            (
              label: [复用增益],
              color: rgb("B85C38"),
              stroke: 1.4pt + rgb("B85C38"),
              data: ((0, 1.1), (1, 8.9), (2, -6.1), (3, -6.9), (4, 30.0), (8, 25.8)),
            ),
          ),
        )
      ],
    )
  ]
]

#let algox(..lines, caption: "", label-name: "algox-ref") = {
  set text(
    font: ("Times New Roman", "SimSun"),
  )
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
