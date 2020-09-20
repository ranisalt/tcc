all:: article.pdf main.pdf slides.pdf
# all::
# 	@latexmk

%.pdf:: %.tex
	@latexmk $^

# main.pdf::
# 	@latexmk main

# slides.pdf::
# 	@latexmk slides

clean::
	@latexmk -C
