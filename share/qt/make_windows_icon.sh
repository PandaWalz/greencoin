#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/greencoin.png
ICON_DST=../../src/qt/res/icons/greencoin.ico
convert ${ICON_SRC} -resize 16x16 greencoin-16.png
convert ${ICON_SRC} -resize 32x32 greencoin-32.png
convert ${ICON_SRC} -resize 48x48 greencoin-48.png
convert greencoin-16.png greencoin-32.png greencoin-48.png ${ICON_DST}

