#!/bin/bash

nvcc -G -Xptxas -v -gencode arch=compute_30,code=sm_30 -I./ -I/Common -I/Cuda main.cu -o crack
