import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
# %matplotlib inline
from matplotlib.ticker import PercentFormatter
import matplotlib.ticker as ticker
import numpy as np
from scipy.signal import argrelextrema
from scipy.signal import find_peaks, peak_prominences

# #-------------Get the data-----------
malFile = pd.read_csv('malicious files day data.csv')[["Sha1ID","Malicious", "Mean", "Std", "Size"]]
cleanFile = pd.read_csv('clean files day data.csv')[["Sha1ID","Malicious", "Mean", "Std", "Size"]]

##change the line by need
dtw5 = pd.read_csv('DTW Distances_5.csv')[["K=5's mean","K=5's median","K=5's std","K=5's malicios percentage"]]
euclidian5 = pd.read_csv('Euclidean Distances_5.csv')[["K=5's mean","K=5's median","K=5's std","K=5's malicios percentage"]]
dtw10 = pd.read_csv('DTW Distances_10.csv')[["K=10's mean","K=10's median","K=10's std","K=10's malicios percentage"]]
euclidian10 = pd.read_csv('Euclidean Distances_10.csv')[["K=10's mean","K=10's median","K=10's std","K=10's malicios percentage"]]
dtw15 = pd.read_csv('DTW Distances_15.csv')[["K=15's mean","K=15's median","K=15's std","K=15's malicios percentage"]]
euclidian15 = pd.read_csv('Euclidean Distances_15.csv')[["K=15's mean","K=15's median","K=15's std","K=15's malicios percentage"]]

features = pd.concat([malFile, cleanFile], axis=0, ignore_index=True)
distances = pd.concat([dtw5, euclidian5], axis=1,ignore_index=True)
distances = pd.concat([distances, dtw10], axis=1,ignore_index=True)
distances = pd.concat([distances, euclidian10], axis=1,ignore_index=True)
distances = pd.concat([distances, dtw15], axis=1,ignore_index=True)
distances = pd.concat([distances, euclidian15], axis=1,ignore_index=True)



features = pd.concat([features, distances],axis=1,ignore_index=True)


features.columns = ["Sha1ID","Malicious","Day count Mean","Day count STD","Size","DTW 5-mean","DTW 5-median",
                    "DTW 5-STD","DTW 5-Malicious(%)", "Euclidean 5-mean","Euclidean 5-median","Euclidean 5-STD",
                    "Euclidean 5-Malicious(%)","DTW 10-mean","DTW 10-median","DTW 10-STD","DTW 10-Malicious(%)",
                    "Euclidean 10-mean","Euclidean 10-median","Euclidean 10-STD","Euclidean 10-Malicious(%)",
                    "DTW 15-mean","DTW 15-median","DTW 15-STD","DTW 15-Malicious(%)",
                    "Euclidean 15-mean","Euclidean 15-median","Euclidean 15-STD","Euclidean 15-Malicious(%)"]
#----max,min,Prevalence--
malFile_array = pd.read_csv('malicious files day data.csv')[["Day_Array"]]
cleanFile_array  = pd.read_csv('clean files day data.csv')[["Day_Array"]]
arrays = pd.concat([malFile_array, cleanFile_array], axis=0, ignore_index=True)
features.insert(4, 'max Day count', 'default value 0')
features.insert(5, 'min Day count', 'default value 0')
features.insert(31, 'Prevalence', 'default value 0')
features.insert(32, 'Peaks',     'default value ')
features.insert(33, 'Sharp peaks','default value ')

for i in range(len(arrays)):
    a = arrays["Day_Array"][i]
    a = map(int, list(a[1:-1].split()))
    a = np.array([int(s) for s in a])
    features.at[i, 'max Day count'] = float(max(a))
    features.at[i, 'min Day count'] = float(min(a))
    features.at[i, 'Prevalence'] = float(sum(a))
    #------Peaks----
    peaks = argrelextrema(a, np.greater, mode='wrap')
    peaks = peaks[0][a[peaks[0]] > 3]
    features.at[i, 'Peaks'] = len(peaks)
    #------Sharp peaks----
    prominences = peak_prominences(a, peaks)[0]
    sharp_peaks_over = peaks
    for j in range(len(peaks) - 1, -1, -1):
        if prominences[j] < 15:
            sharp_peaks_over = np.delete(sharp_peaks_over, j, 0)
    features.at[i, 'Sharp peaks'] = len(sharp_peaks_over)

#create features.csv
parent_dir = os.getcwd()
features.to_csv(os.path.join(parent_dir, "features.csv"))

#------------------------Data exploration---------------------------------
features = pd.read_csv('features.csv')
numoffiles = len(features["Sha1ID"])
# sns.countplot(x='Malicious',data=features)
# plt.show()
malFeature=features[features['Malicious']==True]
cleanFeature=features[features['Malicious']==False]
countMal=len(malFeature)
countClean=len(cleanFeature)
w_mal = np.ones(len(malFeature))/ countMal
w_clean= np.ones(len(cleanFeature))/ countClean
for title in list(features.columns)[2:] :
    new_title = title.strip()
    print(new_title)

    if title == "Malicious":
        sns.countplot(x='Malicious', hue='Malicious', data=features)
        # plt.hist(malFeature[title], weights=w_mal,label="% Malicious out of {0} files".format(countMal)
        #          ,color='r',edgecolor='black',stacked=False)
        # plt.hist(cleanFeature[title], weights=w_clean,
        #          label="% Clean out of {0} files".format(countClean)
        #          , color='b', edgecolor='black',stacked=False)

    elif title == 'Size':
        print("Ojn")
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 1000000, 10000)
        # print(bins)
        width = 2000
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.0)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=0)
        #ax.set_ylim(ymax=1)

        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        # ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif title == "max Day count":
        print("ooooo")
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 200, 5)
        # print(bins)
        width = 2
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=0)
        #ax.set_ylim(ymax=1)

        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        # ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif new_title == "Prevalence":
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 151, 5)
        # print(bins)
        width = 1
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        # ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    # TODO: HERE
    elif (title == "DTW 5-median"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 301, 10)
        # print(bins)
        width = 4
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        # ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif (title == "DTW 10-median"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 301, 10)
        # print(bins)
        width = 4
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        # ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif (title == "DTW 15-median"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 301, 10)
        # print(bins)
        width = 4
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        # ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    #TODO: HERE
    elif (title == "Euclidean 5-median"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 301, 10)
        #print(bins)
        width = 4
        (n,bins,patches) = plt.hist([malFeature[title],cleanFeature[title]],
                                   bins, width=width, weights=[w_mal, w_clean],
                                   label=["% Malicious out of {0} files".format(countMal),
                                          "% Clean out of {0} files".format(countClean)],
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        #ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif (title == "Euclidean 10-median"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 301, 10)
        #print(bins)
        width = 4
        (n,bins,patches) = plt.hist([malFeature[title],cleanFeature[title]],
                                   bins, width=width, weights=[w_mal, w_clean],
                                   label=["% Malicious out of {0} files".format(countMal),
                                          "% Clean out of {0} files".format(countClean)],
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        #ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif (title == "Euclidean 15-median"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 301, 10)
        #print(bins)
        width = 4
        (n,bins,patches) = plt.hist([malFeature[title],cleanFeature[title]],
                                   bins, width=width, weights=[w_mal, w_clean],
                                   label=["% Malicious out of {0} files".format(countMal),
                                          "% Clean out of {0} files".format(countClean)],
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        #ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif (title == "Day count Mean"):
        plt.figure(figsize=(15, 10))

        bins = np.arange(0, 101, 10)
        #print(bins)
        width = 0.1
        (n,bins,patches) = plt.hist([malFeature[title],cleanFeature[title]],
                                   bins, width=width, weights=[w_mal, w_clean],
                                   label=["% Malicious out of {0} files".format(countMal),
                                          "% Clean out of {0} files".format(countClean)],
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
        ax.set_xlim(xmin=min(cleanFeature[title]))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        #ax.set_xlim(xmin=0,xmax=max(features[title]+0.1))
        plt.minorticks_on()
        # ax.xaxis.set_major_locator(ticker.MultipleLocator())

    elif (title == "Day count STD"):
        plt.figure(figsize=(15, 10))
        #bins = np.arange(0, 5)

        bins = np.arange(0, 11, 1)
        #print(bins)
        width = 0.4
        (n,bins,patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                   bins=bins, width=width, weights=[w_mal, w_clean],
                                   label=["% Malicious out of {0} files".format(countMal),
                                          "% Clean out of {0} files".format(countClean)],
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.MaxNLocator(11))
        ax.xaxis.set_minor_locator(ticker.MaxNLocator(1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper right')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()

    #TODO: HERE
    elif (title == "DTW 5-Malicious(%)"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 101, 10)
        width = 0.4
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n,bins,patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                   bins=bins,  weights=[w_mal, w_clean], label=label,
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper left')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "DTW 10-Malicious(%)"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 101, 10)
        width = 0.4
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n,bins,patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                   bins=bins,  weights=[w_mal, w_clean], label=label,
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper left')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "DTW 15-Malicious(%)"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 101, 10)
        width = 0.4
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n,bins,patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                   bins=bins,  weights=[w_mal, w_clean], label=label,
                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))

        plt.legend(loc='upper left')
        plt.title ("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    #TODO: HERE
    elif title == 'Euclidean 5-Malicious(%)':
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 101, 5)
        width = 0.4
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper left')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif title == 'Euclidean 10-Malicious(%)':
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 101, 5)
        width = 0.4
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper left')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif title == 'Euclidean 15-Malicious(%)':
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 101, 5)
        width = 0.4
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper left')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    #TODO: HERE
    elif (title == "DTW 5-STD"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "DTW 10-STD"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "DTW 15-STD"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    #TODO: HERE
    elif (title == "Euclidean 5-STD"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Euclidean 10-STD"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Euclidean 15-STD"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    #TODO: HERE
    elif (title == "DTW 5-mean"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "DTW 10-mean"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "DTW 15-mean"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    #TODO: HERE
    elif (title == "Euclidean 5-mean"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Euclidean 10-mean"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Euclidean 15-mean"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)

        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Prevalence"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Peaks"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    elif (title == "Sharp peaks"):
        plt.figure(figsize=(15, 10))
        bins = np.arange(0, 51, 1)
        width = 0.1
        label = ["% Malicious out of {0} files".format(countMal),
                 "% Clean out of {0} files".format(countClean)]
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins=bins, weights=[w_mal, w_clean], label=label,
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        # ax.xaxis.set_major_locator(ticker.IndexLocator(base=10, offset=-1))
        ax.set_xlim(xmin=0)
        ax.set_ylim(ymax=1)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("{0} Distribution".format(title))
        plt.ylabel("Percentage")
        plt.xlabel("{0}".format(title))
        plt.tight_layout()
        plt.minorticks_on()
        ax.xaxis.set_tick_params(which='minor', bottom=False)

    path = os.path.join(parent_dir, "{0} Distribution.png".format(title))
    plt.savefig(path)
    plt.clf()
    plt.close()
    #print("{0}\n".format(title))

