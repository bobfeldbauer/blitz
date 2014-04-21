#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/BlitzCoin.ico

convert ../../src/qt/res/icons/BlitzCoin-16.png ../../src/qt/res/icons/BlitzCoin-32.png ../../src/qt/res/icons/BlitzCoin-48.png ${ICON_DST}
