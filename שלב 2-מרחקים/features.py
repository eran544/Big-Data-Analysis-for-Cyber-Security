import pandas as pd
import os
import  numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
# %matplotlib inline

#-------------Get the data-----------
malFile = pd.read_csv('malicious files day data.csv')[["Sha1ID","Malicious", "mean", "std", "size"]]
cleanFile = pd.read_csv('clean files day data.csv')[["Sha1ID","Malicious", "mean", "std", "size"]]

dtw = pd.read_csv('DTW Distances.csv')[["k's mean","k's median","k's std","k's malicios percentage"]]
euclidian = pd.read_csv('Euclidean Distances.csv')[["k's mean","k's median","k's std","k's malicios percentage"]]

features = pd.concat([malFile, cleanFile], axis=0, ignore_index=True)
distances = pd.concat([dtw, euclidian], axis=1,ignore_index=True)

features = pd.concat([features, distances],axis=1,ignore_index=True)

features.columns = ["Sha1ID","Malicious","Day count Mean","Day count STD","Size","DTW k-mean","DTW k-median","DTW k-STD","DTW k-Malicious(%)",
                    "Euclidean k-mean","Euclidean k-median","Euclidean k-STD","Euclidean k-Malicious(%)"]
#----max,min--
malFile_array = pd.read_csv('malicious files day data.csv')[["day_Array"]]
cleanFile_array  = pd.read_csv('clean files day data.csv')[["day_Array"]]
arrays = pd.concat([malFile_array, cleanFile_array], axis=0, ignore_index=True)
features.insert(4, 'max Day count', 'default value 0')
features.insert(5, 'min Day count', 'default value 0')
for i in range(len(arrays)):
    a = arrays["day_Array"][i]
    a = map(int, list(a[1:-1].split()))
    a = np.array([int(s) for s in a])
    features.at[i, 'max Day count'] = float(max(a))
    features.at[i, 'min Day count'] = float(min(a))

#create features.csv
parent_dir = os.getcwd()
# features.to_csv(os.path.join(parent_dir, "features.csv"))

#------------------------Data exploration---------------------------------

# sns.countplot(x='Malicious',data=features)
# plt.show()
for title in list(features.columns) :
    # plt.title("file {0}: Machine per Day".format(fileSha))
    if(title!="Sha1ID"):
        # sns.set(style="darkgrid")
        # plt.figure(figsize=(12, 8))
        # ax=sns.countplot(x=title,hue='Malicious',data=features)
        # # ax.set_xticklabels(ax.get_xticklabels(), rotation=40, ha="right",fontsize=7)
        # # plt.tight_layout()
        if (title != "Malicious" and title!='max Day count' and title!='min Day count'):
             # features.hist(column=title, bins='auto',figsize=(12, 8),xrot=14)
             g = sns.catplot(x=title, hue="Malicious", col="Malicious",
                             data=features, kind="count",
                             )
             g.set(ylim=(0, max(features[title].tolist())+1))

        #     # fig = plt.figure()
        #     x=features[title].tolist()
        #     plt.hist(x, bins=10)
        #     plt.xticks(rotation=35)
        #     plt.tick_params(axis='x', which='major', labelsize=7)
        #     plt.tight_layout()
        # ax.set_ylim(auto=True)
        #features.hist(column=title, bins=50)
        # plt.tight_layout()
        path = os.path.join(parent_dir, "{0} Distribution.png".format(title))
        plt.savefig(path)
        # plt.show()
        plt.clf()
        plt.close()
        print("{0}\n".format(title))
