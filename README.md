# MalNet
MalNet is Malware Detector using deep machine learning algorithms to classify windows executable to malware or benign. The model constructed using keras with 2 hidden layers of fully connected neurons (250 neurons and 100 neurons respectively) and was trained by [EMBER Dataset](https://github.com/endgameinc/ember) (600K files) and achieved 95% accuaracy from the test set (200K files)
## Installation
First install the requirements
```
pip install -r requirements.txt
```
There is already trained model in `MalNet\TrainedModel` you can use it to classify PE files.
```
Python predictor.py
```
If you want to train the model yourself:<br>
Process the EMBER dataset and generate vectorized training input
```
Python MalNet\features_extractor.py
```
The vectorized version of the features will be generated in `MalNel\Vectors`.<br>
To train the model and save the parameters of the model.
```
Python MalNet\train.py
```
The model will saved in `MalNet\TrainedModel`.<br>

## Scripts
The `APIs_extractor.py` script parses through the dataset and generate the most 1k imported malicious Windows APIs by the malwares to use in the features. The generated APIs are in MalNet/apis.txt.  
The `features.py.py` script is class to extract and process the features from the dataset (JSON) or from the raw executable files (EXE/DLL/SYS)

## Features  
The features vector has of 1,347 columns from different sections of PE  
- 1000 columns for the used APIs from the predefined malicious APIs (listed in MalNet/apis.txt).
- 256 columns for the entropy of each byte.
- 21 columns  for `virtual size` ,`raw size`,`virtual address` ,`entropy` and `characteristics` of the sections `.text`, `.data` and `rsrc`.
- 22 columns for different value of `Optional Header` and `File Header` such as `sizeof_code` , `sizeof_headers`,`sizeof_heap_commit`, `symbols` ...
- 7 columns for strings description in the executable such as number of string, average length, number of URLs, number of file paths, number of registry keys...
- 30 columns for `virtual size` and `virtual address` of the 15 entries of Data Directories.
- 11 columns for some extra strong indicators of malwares such as the entropy of the whole file, indicator for section that has both READ and EXECUTE attributes (indicates self-modifying code) or whether the entry point is not on .text or .CODE section (otherwise it's probably executable hijacking)


