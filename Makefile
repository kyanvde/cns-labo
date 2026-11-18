LATEXMK   := latexmk -pdf -interaction=nonstopmode -halt-on-error -cd
SOLUTIONS := $(shell find . -name solution.tex -not -path './.*')

.PHONY: all report solutions clean

all: report solutions

report:
	$(LATEXMK) report.tex

solutions:
	$(LATEXMK) $(SOLUTIONS)

clean:
	$(LATEXMK) -C report.tex $(SOLUTIONS)
