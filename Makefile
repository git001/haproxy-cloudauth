# Makefile of the cloudauth addon.
#
# The filter itself is built by the HAProxy Makefile, which includes
# Makefile.mk (see README.md). This Makefile only provides the helper targets:
#
#   make pdf   : builds the PDF manuals into build/, from the Markdown ones in
#                doc/, with pandoc and its typst engine. It is skipped if one
#                of them is missing.
#   make clean : removes build/.
#
# The tools are looked up in the PATH, and may be set with PANDOC and TYPST.

PANDOC ?= pandoc
TYPST  ?= typst

DOCS := configuration management internals-api
PDFS := $(addprefix build/,$(addsuffix .pdf,$(DOCS)))

.PHONY: all pdf clean

all:
	@echo "The filter is built with HAProxy, see README.md. Targets: pdf, clean."

pdf:
	@if ! command -v $(PANDOC) >/dev/null 2>&1; then \
		echo "pdf: skipped, pandoc not found (set PANDOC=/path/to/pandoc)."; \
	elif ! command -v $(TYPST) >/dev/null 2>&1; then \
		echo "pdf: skipped, typst not found (set TYPST=/path/to/typst)."; \
	else \
		$(MAKE) --no-print-directory $(PDFS); \
	fi

# The first heading of each manual becomes the title of the document, shown
# on the cover page with the metadata of doc/pdf-metadata.yaml and the text
# moved there by doc/pdf-cover.lua. doc/pdf-style.typ sets the page layout.
PDF_DEPS := doc/pdf-metadata.yaml doc/pdf-cover.lua doc/pdf-style.typ

build/%.pdf: doc/%.md $(PDF_DEPS)
	@mkdir -p build
	$(PANDOC) --from=markdown --pdf-engine=$(TYPST) --shift-heading-level-by=-1 \
		--metadata-file=doc/pdf-metadata.yaml --lua-filter=doc/pdf-cover.lua \
		--toc --include-in-header=doc/pdf-style.typ -V papersize=a4 -o $@ $<

clean:
	rm -rf build
