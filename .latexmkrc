@default_files = ('main.tex', 'slides.tex');

$pdflatex = "xelatex -shell-escape -synctex=1 %O %S";
$pdf_mode = 1;
$dvi_mode = $postscript_mode = 0;
