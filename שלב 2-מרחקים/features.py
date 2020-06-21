import pandas as pd
import os
import  numpy as np

malFile = pd.read_csv('malicious files day data.csv')[["Sha1ID","Malicious", "mean", "std", "size"]]
cleanFile = pd.read_csv('clean files day data.csv')[["Sha1ID","Malicious", "mean", "std", "size"]]

dtw = pd.read_csv('DTW Distances.csv')[["k's mean","k's median","k's std","k's malicios percentage"]]
euclidian = pd.read_csv('Euclidean Distances.csv')[["k's mean","k's median","k's std","k's malicios percentage"]]

features = pd.concat([malFile, cleanFile], axis=0, ignore_index=True)
distances = pd.concat([dtw, euclidian], axis=1,ignore_index=True)

features = pd.concat([features, distances],axis=1,ignore_index=True)

features.columns = ["Sha1ID","Malicious","Day count Mean","Day count STD","Size","DTW k-mean","DTW k-median","DTW k-STD","DTW k-Malicious(%)",
                    "Euclidean k-mean","Euclidean k-median","Euclidean k-STD","Euclidean k-Malicious(%)"]
#----max--
malFile_array = pd.read_csv('malicious files day data.csv')[["day_Array"]]
cleanFile_array  = pd.read_csv('clean files day data.csv')[["day_Array"]]
arrays = pd.concat([malFile_array, cleanFile_array], axis=0, ignore_index=True)
features.insert(4, 'max Day count', 'default value 0')
features.insert(5, 'min Day count', 'default value 0')
for i in range(len(arrays)):
    a = arrays["day_Array"][i]
    a = map(int, list(a[1:-1].split()))
    a = np.array([int(s) for s in a])
    features.at[i, 'max Day count'] = max(a)
    features.at[i, 'min Day count'] = min(a)
    # features.ix[["max", i]] =max(a)
    # features.ix[["max", i]]=min(a)





parent_dir = os.getcwd()
features.to_csv(os.path.join(parent_dir, "features.csv"))
