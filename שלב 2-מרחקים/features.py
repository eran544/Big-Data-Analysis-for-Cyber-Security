import pandas as pd
import os
import  numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
# %matplotlib inline
from matplotlib.ticker import PercentFormatter
import matplotlib.ticker as ticker

# #-------------Get the data-----------
# malFile = pd.read_csv('malicious files day data.csv')[["Sha1ID","Malicious", "mean", "std", "size"]]
# cleanFile = pd.read_csv('clean files day data.csv')[["Sha1ID","Malicious", "mean", "std", "size"]]
#
# dtw = pd.read_csv('DTW Distances.csv')[["k's mean","k's median","k's std","k's malicios percentage"]]
# euclidian = pd.read_csv('Euclidean Distances.csv')[["k's mean","k's median","k's std","k's malicios percentage"]]
#
# features = pd.concat([malFile, cleanFile], axis=0, ignore_index=True)
# distances = pd.concat([dtw, euclidian], axis=1,ignore_index=True)
#
# features = pd.concat([features, distances],axis=1,ignore_index=True)
#
# features.columns = ["Sha1ID","Malicious","Day count Mean","Day count STD","Size","DTW k-mean","DTW k-median","DTW k-STD","DTW k-Malicious(%)",
#                     "Euclidean k-mean","Euclidean k-median","Euclidean k-STD","Euclidean k-Malicious(%)"]
# #----max,min--
# malFile_array = pd.read_csv('malicious files day data.csv')[["day_Array"]]
# cleanFile_array  = pd.read_csv('clean files day data.csv')[["day_Array"]]
# arrays = pd.concat([malFile_array, cleanFile_array], axis=0, ignore_index=True)
# features.insert(4, 'max Day count', 'default value 0')
# features.insert(5, 'min Day count', 'default value 0')
# for i in range(len(arrays)):
#     a = arrays["day_Array"][i]
#     a = map(int, list(a[1:-1].split()))
#     a = np.array([int(s) for s in a])
#     features.at[i, 'max Day count'] = float(max(a))
#     features.at[i, 'min Day count'] = float(min(a))
#
# #create features.csv
parent_dir = os.getcwd()
# # features.to_csv(os.path.join(parent_dir, "features.csv"))

#------------------------Data exploration---------------------------------
features = pd.read_csv('features.csv')

# sns.countplot(x='Malicious',data=features)
# plt.show()
malFeature=features[features['Malicious']==True]
cleanFeature=features[features['Malicious']==False]
countMal=len(malFeature)
countClean=len(cleanFeature)
w_mal = np.ones(len(malFeature))/ countMal
w_clean= np.ones(len(cleanFeature))/ countClean
for title in list(features.columns)[2:] :
    if (title == "Malicious"):
        sns.countplot(x='Malicious', hue='Malicious', data=features)

    else:
        # plt.hist(malFeature[title], weights=w_mal,label="% Malicious out of {0} files".format(countMal)
        #          ,color='r',edgecolor='black',stacked=False)
        # plt.hist(cleanFeature[title], weights=w_clean,
        #          label="% Clean out of {0} files".format(countClean)
        #          , color='b', edgecolor='black',stacked=False)

        (n,bins,patches) =plt.hist([malFeature[title],cleanFeature[title]], weights=[w_mal,w_clean], label=["% Malicious out of {0} files".format(countMal),"% Clean out of {0} files".format(countClean)]
                 , color=['r','b'], edgecolor='black')
        plt.gca().yaxis.set_major_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        ax = plt.gca()
        #ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())


    path = os.path.join(parent_dir, "{0} Distribution.png".format(title))
    plt.savefig(path)
    plt.clf()
    plt.close()
    print("{0}\n".format(title))
