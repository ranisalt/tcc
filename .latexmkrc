@default_files = ('main.tex');

$pdflatex = "xelatex -synctex=1 %O %S";
$pdf_mode = 1;
$dvi_mode = $postscript_mode = 0;
