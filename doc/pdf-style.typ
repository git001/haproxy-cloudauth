// Typst rules of the PDF manuals, included by pandoc (see "make pdf").

// The cover page holds the title, the authors and the text before the first
// section (see doc/pdf-cover.lua). It replaces the title block of the pandoc
// template, whose conf() function is wrapped.
#let pandoc-conf = conf
#let conf(title: none, authors: (), abstract-title: none, abstract: none, ..args) = {
  let cover = page(numbering: none)[
    #v(1fr)
    #align(center)[
      #set par(justify: false)
      #text(weight: "bold", size: 2em, hyphenate: false)[#title]
      #v(2em)
      #for author in authors [
        Author: #author.name #if author.email != [] [\<#author.email\>] \
      ]
    ]
    #v(2em)
    #abstract
    #v(2fr)
  ]
  set document(title: title) if title != none
  pandoc-conf(authors: authors, ..args.named(), cover + args.pos().at(0))
}

// The table of contents and each top level section start on a new page.
#show outline: it => { pagebreak(weak: true); it }
#show heading.where(level: 1): it => { pagebreak(weak: true); it }

// The code blocks, mostly configuration examples, use a smaller font so that
// their long lines fit, and a light background.
#show raw.where(block: true): set text(size: 7pt)
#show raw.where(block: true): it => block(fill: luma(244), inset: 6pt, radius: 2pt, width: 100%, it)
