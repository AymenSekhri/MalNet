#Train the model using Keras.
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = "0"
import warnings
warnings.filterwarnings("ignore")
import tensorflow as tf
from tensorflow import keras
import numpy as np
import matplotlib.pyplot as plt
from sklearn import preprocessing
import struct
import joblib



vectors_path = "MalNet\\Vectors\\"
def unison_shuffled(a, b):
    assert len(a) == len(b)
    p = np.random.permutation(len(a))
    return a[p], b[p]

#Opening np vectors from disk
x_train = np.lib.format.open_memmap(vectors_path + "x_train.data", dtype=np.float32, mode="r")
y_train = np.lib.format.open_memmap(vectors_path + "y_train.data", dtype=np.float32, mode="r")
x_test = np.lib.format.open_memmap(vectors_path + "x_test.data", dtype=np.float32, mode="r")
y_test = np.lib.format.open_memmap(vectors_path + "y_test.data", dtype=np.float32, mode="r")

#Normlazing
minmax_scale = preprocessing.MinMaxScaler().fit(x_train)
x_train = minmax_scale.transform(x_train)
x_test = minmax_scale.transform(x_test)


#shufling training set
x_train,y_train = unison_shuffled(x_train,y_train)

#Defining The model : 2 hidden layers 250-100 neurons with dropout of 50% each 
model = keras.Sequential()
model.add(keras.layers.Dense(250,activation='relu'))
model.add(keras.layers.Dropout(0.5))
model.add(keras.layers.Dense(100,activation='relu'))
model.add(keras.layers.Dropout(0.5))
model.add(keras.layers.Dense(1,activation='sigmoid'))
model.compile(tf.train.AdamOptimizer() ,loss=keras.losses.mean_squared_error ,metrics=['accuracy'])
model.fit(x=x_train,y=y_train,batch_size=200,epochs=10,validation_split=0.0)

#Evaluate the model using test set
scores = model.evaluate(x_test, y_test)
print("Test Loss : {}    Test Accuarcy : {}%".format(scores[0],scores[1] * 100))

#Saving Model
joblib.dump(minmax_scale, 'MalNet\\scaler.pkl')     #Saving normalization scale object
model.save("MalNet\\weights_and_architecture.h5")   #Saving Keras model
print("Model Has Been Saved")