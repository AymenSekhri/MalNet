from xml.dom import minidom
import pyperclip
import numpy as np
import json
import tqdm
import multiprocessing
from MalNet.features_processing import features_processing

def Vectorize_features(Output,ft,nrow,features_json):
    #Create np vector on disk
    X_file = np.lib.format.open_memmap(Output.format("x"), dtype=np.float32, mode="r+", shape=(NumberOfLabledData, ft.dim))
    Y_file = np.lib.format.open_memmap(Output.format("y"), dtype=np.float32, mode="r+", shape=(NumberOfLabledData,1))
    #Write the features to the vector on disk
    X_file[nrow,0:ft.dim] ,Y_file[nrow] = ft.VectorizeFromJson(features_json)
def Vectorize_wrapper(args):
       return Vectorize_features(*args)
def GetDatasetLines(Paths,count):
    i = 0
    for path in Paths:
        with open(path, "r") as f:
            for x in f:
                if (count == -1 or count > i) and json.loads(x)["label"] != -1:
                    i +=1
                    yield  x
NumberOfLabledData = 0
def VectorizeJson(InPaths,OutPath):
    ft = features_processing()
    NumberOfSamplesToRead = -1
    #Read Dataset
    pool = multiprocessing.Pool()
    poolarg = [[OutPath,ft,nrow,line] for nrow,line in enumerate(GetDatasetLines(InPaths,NumberOfSamplesToRead))]
    NumberOfLabledData = len(poolarg)
    #Prepare Files
    X_file = np.lib.format.open_memmap(OutPath.format("x"), dtype=np.float32, mode="w+", shape=(NumberOfLabledData, ft.dim))
    Y_file = np.lib.format.open_memmap(OutPath.format("y"), dtype=np.float32, mode="w+", shape=(NumberOfLabledData,1))
    del X_file,Y_file
    #for x in range(3):
    #    Vectorize_wrapper(poolarg[x])
    #Use multi-processing to execute the vectorizing function
    for x in tqdm.tqdm(pool.imap_unordered(Vectorize_wrapper,poolarg),total=NumberOfLabledData):
        pass
if __name__ == '__main__':
    
    dataset_path = "D:\\Downloads\\IDM\\Compressed\\dataset\\ember2018\\"
    print("Processing the training set")
    Train_Dataset_Paths = [(dataset_path + "train_features_{}.jsonl").format(i) for i in range(6)]
    VectorizeJson(Train_Dataset_Paths, "MalNet\\Vectors\\{}_train.data")
    
    print("Processing the test set")
    Test_Dataset_Paths = [dataset_path + "test_features.jsonl"]
    VectorizeJson(Test_Dataset_Paths,"MalNet\\Vectors\\{}_test.data")
    print("Dataset processing has been completed.")
