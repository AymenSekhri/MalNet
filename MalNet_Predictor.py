#Load the model and evaluate it.
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = "0"
import warnings
warnings.filterwarnings("ignore")

import tensorflow as tf
from tensorflow import keras
import numpy as np
import joblib
import lief
from MalNet.features import Features

MyFeatures = Features()

def IsValidPE(path):
    PE = lief.parse(path)
    if PE == None:
        del PE
        return False
    del PE
    return True

def Predict(path):
    #Loading Model
    minmax_scale = joblib.load('model\\scaler.pkl')
    model = tf.compat.v1.keras.models.load_model("model\\weights_and_architecture.h5")
    model.compile(tf.train.AdamOptimizer() ,loss=keras.losses.mean_squared_error ,metrics=['accuracy'])
    if IsValidPE(path) == False:
        return -1,-1
    X_vector = MyFeatures.VectorizeFromRawFile(path)
    X_vector = minmax_scale.transform([X_vector,X_vector])
    score = model.predict(np.array(X_vector))
    thres = 0.7
    if score[0][0] > thres:
        return 1,100 * (score[0][0] - thres) / (1 - thres)
    else:
        return 0,100 * (thres - score[0][0]) / thres
    del X_vector
#Evaluate the model
if __name__ == "__main__":
    while True:
        print("\033[1;37;40mEnter File Path : ")
        d = input("").replace("\"","",-1)
        result,score = Predict(d)
        if result == -1 :
            print("\033[1;37;40mInvalid File Format.")
        elif result == 1:
            print("\033[1;31;40mMalware Executable Detected. Confidance Score {0:.2f}%.".format(score))
        elif result == 0:
            print("\033[1;32;40mClean Executable. Confidance Score {0:.2f}%.".format(score))
        del d
        
#pipreqs
