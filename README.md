# MalNet
MalNet is Malware Detector using deep machine learning algorithms to classify windows executables to malware or benign.The model constructed using keras with 2 hidden layers of fully connected neurons (250 neuron and 100 neuron respectively) and was trained by [EMBER dataset](https://github.com/endgameinc/ember) EMBER Dataset (600K files) and archived 95% accuarcy from the the test set (K files)
## install
First install the requirements
```
pip install requirements.txt
```
Process the EMBER dataset and generate the taining input data
```
Python MalNet/features_extractor.py
```
Train the model and save the parametrs of the model.
```
Python MalNet/train.py
```
Use the model to classify PE files
```
Python MalNet_Predictor.py
```
