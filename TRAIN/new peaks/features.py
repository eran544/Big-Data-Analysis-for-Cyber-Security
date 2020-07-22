from builtins import print

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
    if features.at[i, 'max Day count']==468919
        print("ssd")
    peaks = argrelextrema(a, np.greater, mode='wrap')
    peaks = peaks[0][a[peaks[0]] > 4]
    features.at[i, 'Peaks'] = len(peaks)
    #------Sharp peaks----
    prominences = peak_prominences(a, peaks)[0]
    sharp_peaks_over = peaks
    for j in range(len(peaks) - 1, -1, -1):
        if prominences[j] < 10:
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

def percentage(part, whole):
    return 100 * float(part) / float(whole)

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

    elif (title == "Peaks"):
        plt.figure(figsize=(10, 7))
        malDist = malFeature[title]
        cleanDist = cleanFeature[title]

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()

        malMissingVals = pd.Series([0], index=[5])
        # cleanMissingVals = pd.Series([0], index=[1])

        malVal = malVal.append(malMissingVals)
        # cleanVal = cleanVal.append(cleanMissingVals)
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)
        print(malVal, cleanVal)

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))

        ind = np.arange(6)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('Peaks)')
        plt.title('Peaks Distribution', fontweight="bold")
        plt.xticks(ind, ('0', '1', '2', '3', '4', '5'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Malicious out of {0} files".format(countMal),
                                    "% Clean out of {0} files".format(countClean)))

    elif (title == "Sharp peaks"):
        plt.figure(figsize=(10, 7))
        malDist = malFeature[title]
        cleanDist = cleanFeature[title]
        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()

        malMissingVals = pd.Series([0], index=[3])
        # cleanMissingVals = pd.Series([0], index=[1])

        malVal = malVal.append(malMissingVals)
        # cleanVal = cleanVal.append(cleanMissingVals)
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)
        print(malVal, cleanVal)

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))

        ind = np.arange(4)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('Sharp SPeaks)')
        plt.title('Sharp Peaks Distribution', fontweight="bold")
        plt.xticks(ind, ('0', '1', '2', '3', '4', '5', '6'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Malicious out of {0} files".format(countMal),
                                    "% Clean out of {0} files".format(countClean)))

    elif (title == "DTW 5-Malicious(%)"):
        plt.figure(figsize=(7, 5))
        ax = plt.gca()

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)

        ind = np.arange(6)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('5-Malicious (%)')
        plt.title('DTW 5-Malicious', fontweight="bold")
        plt.xticks(ind, ('0', '20', '40', '60', '80', '100'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Clean out of {0} files".format(countClean),
                                    "% Malicious out of {0} files".format(countMal)))
        plt.tight_layout()

    elif (title == "DTW 10-Malicious(%)"):
        plt.figure(figsize=(7, 5))
        ax = plt.gca()

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()

        malMissingVals = pd.Series([0], index=[90])
        cleanMissingVals = pd.Series([0,0], index=[90,100])

        malVal = malVal.append(malMissingVals)
        cleanVal = cleanVal.append(cleanMissingVals)
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))

        ind = np.arange(11)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('10-Malicious (%)')
        plt.title('DTW 10-Malicious', fontweight="bold")
        plt.xticks(ind, ('0', '10', '20', '30', '40', '50', '60', '70', '80', '90', '100'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Clean out of {0} files".format(countClean),
                                    "% Malicious out of {0} files".format(countMal)))
        plt.tight_layout()

    elif (title == "DTW 15-Malicious(%)"):
        plt.figure(figsize=(7, 5))
        ax = plt.gca()
        pd.options.display.float_format = "{:,.2f}".format

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()
        malMissingVals = pd.Series([0,0], index=[73.33, 100.0])
        cleanMissingVals = pd.Series([0,0,0,0,0,0], index=[66.67, 73.33, 80.00, 86.67, 93.33, 100.00])

        malVal = malVal.append(malMissingVals)
        cleanVal = cleanVal.append(cleanMissingVals)
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))

        ind = np.arange(16)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence
        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('15-Malicious (%)')
        plt.title('DTW 15-Malicious', fontweight="bold")
        plt.xticks(ind, ('0.00', '6.67', '13.33', '20.00', '26.67', '33.33', '40.00', '46.67',
                         '53.33', '60.00', '66.67', '73.33', '80.00', '86.67', '93.33', '100.00'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Clean out of {0} files".format(countClean),
                                    "% Malicious out of {0} files".format(countMal)))
        plt.tight_layout()


    elif title == 'Euclidean 5-Malicious(%)':
        plt.figure(figsize=(7, 5))
        ax = plt.gca()

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)

        ind = np.arange(6)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('5-Malicious (%)')
        plt.title('Euclidean 5-Malicious', fontweight="bold")
        plt.xticks(ind, ('0', '20', '40', '60', '80', '100'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Clean out of {0} files".format(countClean),
                                    "% Malicious out of {0} files".format(countMal)))
        plt.tight_layout()

    elif title == 'Euclidean 10-Malicious(%)':
        plt.figure(figsize=(7, 5))
        ax = plt.gca()

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()
        malMissingVals = pd.Series([0,0,0,0], index=[70,80,90,100])
        data = np.array([0,0])
        cleanMissingVals = pd.Series(data, index=[90,100])
        malVal = malVal.append(malMissingVals)
        cleanVal = cleanVal.append(cleanMissingVals)
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))

        ind = np.arange(11)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('10-Malicious (%)')
        plt.title('Euclidean 10-Malicious', fontweight="bold")
        plt.xticks(ind, ('0', '10', '20', '30', '40', '50', '60', '70', '80', '90', '100'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Clean out of {0} files".format(countClean),
                                    "% Malicious out of {0} files".format(countMal)))

    elif title == 'Euclidean 15-Malicious(%)':
        plt.figure(figsize=(10, 7))
        ax = plt.gca()
        pd.options.display.float_format = "{:,.2f}".format

        malVal = malFeature[title].value_counts()
        cleanVal = cleanFeature[title].value_counts()
        malMissingVals = pd.Series([0,0,0,0,0,0,0], index=[60.00, 66.67, 73.33, 80.00, 86.67, 93.33, 100.0])
        cleanMissingVals = pd.Series([0,0,0,0,0,0], index=[66.67, 73.33, 80.00, 86.67, 93.33, 100.00])
        malVal = malVal.append(malMissingVals)
        cleanVal = cleanVal.append(cleanMissingVals)
        malVal.sort_index(inplace=True)
        cleanVal.sort_index(inplace=True)
        print(malVal, cleanVal)

        mal = []
        clean = []
        for f in malVal:
            mal.append(percentage(f, len(malFeature[title])))
        for f in cleanVal:
            clean.append(percentage(f, len(cleanFeature[title])))

        ind = np.arange(16)  # the x locations for the groups
        width = 0.4  # the width of the bars: can also be len(x) sequence
        p1 = plt.bar(ind - 0.2, mal, width, color="red")
        p2 = plt.bar(ind + 0.2, clean, width, color="blue")
        plt.ylabel('Percentages')
        plt.xlabel('15-Malicious (%)')
        plt.title('Euclidean 15-Malicious', fontweight="bold")
        plt.xticks(ind, ('0.00', '6.67', '13.33', '20.00', '26.67', '33.33', '40.00', '46.67',
                         '53.33', '60.00', '66.67', '73.33', '80.00', '86.67', '93.33', '100.00'))
        plt.yticks(np.arange(0, 101, 5))
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        plt.legend((p1[0], p2[0]), ("% Clean out of {0} files".format(countClean),
                                    "% Malicious out of {0} files".format(countMal)))
        plt.tight_layout()

    # elif title == 'Size':
    #     plt.figure(figsize=(15, 7))
    #     bins = np.arange(0, 1501, 50)
    #     width = 10
    #     kbSizeMal = malFeature[title] / 1000
    #     kbSizeClean = cleanFeature[title] / 1000
    #
    #     (n, bins, patches) = plt.hist([kbSizeMal, kbSizeClean],
    #                                   bins=bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     plt.rc('font', weight='bold')
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=0)
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.legend(loc='upper right')
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0} (KB)".format(title), fontweight='bold')
    #     plt.tight_layout()

    # elif new_title == "Prevalence":
    #     plt.figure(figsize=(15, 10))
    #     bins = np.arange(0, 150, 5)
    #     width = 1
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_minor_formatter(ticker.ScalarFormatter(0))
    #     ax.set_xlim(xmin=0)
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()

    # elif (title == "DTW 5-median"):
    #     plt.figure(figsize=(7, 10))
    #     bins = np.arange(0, 101, 10)
    #     width = 4
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=min(cleanFeature[title]))
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()
    #
    # elif (title == "DTW 10-median"):
    #     plt.figure(figsize=(7, 10))
    #     bins = np.arange(0, 101, 10)
    #     width = 4
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=min(cleanFeature[title]))
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()
    #
    # elif (title == "DTW 15-median"):
    #     plt.figure(figsize=(10, 10))
    #     bins = np.arange(0, 150.5, 10)
    #     width = 4
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=min(cleanFeature[title]))
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()
    #
    # elif (title == "Euclidean 5-median"):
    #     plt.figure(figsize=(7, 10))
    #     bins = np.arange(0, 101, 10)
    #     width = 4
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=min(cleanFeature[title]))
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()
    #
    # elif (title == "Euclidean 10-median"):
    #     plt.figure(figsize=(7, 10))
    #     bins = np.arange(0, 101, 10)
    #     width = 4
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=min(cleanFeature[title]))
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()
    #
    #
    # elif (title == "Euclidean 15-median"):
    #     plt.figure(figsize=(10, 10))
    #     bins = np.arange(0, 150.5, 10)
    #     width = 4
    #     (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
    #                                   bins, width=width, weights=[w_mal, w_clean],
    #                                   label=["% Malicious out of {0} files".format(countMal),
    #                                          "% Clean out of {0} files".format(countClean)],
    #                                   color=['r', 'b'], edgecolor='black', linewidth=0.5)
    #     ax = plt.gca()
    #     ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
    #     ax.set_xlim(xmin=min(cleanFeature[title]))
    #     ax.yaxis.set_major_formatter(PercentFormatter(1))
    #     ax.yaxis.set_minor_formatter(PercentFormatter(1))
    #
    #     plt.legend(loc='upper right')
    #     plt.title("{0} Distribution".format(title), fontweight='bold')
    #     plt.ylabel("Percentage")
    #     plt.xlabel("{0}".format(title))
    #     plt.tight_layout()
    #     plt.minorticks_on()

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

    elif title == "max Day count":
        plt.figure(figsize=(12, 7))
        bins = np.arange(0, 51, 1)
        width = 0.4
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("Max Downloads Per Day Distribution", fontweight="bold")
        plt.ylabel("Percentage")
        plt.xlabel("Max Downloads Per Day")
        plt.tight_layout()

    elif (title == "Day count Mean"):
        plt.figure(figsize=(10, 7))
        bins = np.arange(0, 21, 1)
        width = 0.4
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("Mean of Downloads Per Day Distribution", fontweight="bold")
        plt.ylabel("Percentage")
        plt.xlabel("Downloads Per Day")
        plt.tight_layout()

    elif (title == "Day count STD"):
        plt.figure(figsize=(10, 7))
        bins = np.arange(0, 21, 1)
        width = 0.4
        (n, bins, patches) = plt.hist([malFeature[title], cleanFeature[title]],
                                      bins, width=width, weights=[w_mal, w_clean],
                                      label=["% Malicious out of {0} files".format(countMal),
                                             "% Clean out of {0} files".format(countClean)],
                                      color=['r', 'b'], edgecolor='black', linewidth=0.5)
        ax = plt.gca()
        ax.xaxis.set_major_locator(ticker.FixedLocator(bins))
        ax.set_xlim(xmin=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_minor_formatter(PercentFormatter(1))
        plt.legend(loc='upper right')
        plt.title("Standard Deviation of Downloads Per Day Distribution", fontweight="bold")
        plt.ylabel("Percentage")
        plt.xlabel("Downloads Per Day")
        plt.tight_layout()

    path = os.path.join(parent_dir, "{0} Distribution.png".format(title))
    plt.savefig(path)
    plt.clf()
    plt.close()
    #print("{0}\n".format(title))

