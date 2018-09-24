#!/bin/bash

lspci | grep 'Tesla M60'
is_teslam60=$?
if [ $is_teslam60 -eq 0 ]; then
	nvcc -Xptxas -v -gencode arch=compute_52,code=sm_52 -I./ -I/Common -I/Cuda main.cu -o crack
	exit 0
fi

nvcc -Xptxas -v -gencode arch=compute_52,code=sm_52 -I./ -I/Common -I/Cuda main.cu -o crack
