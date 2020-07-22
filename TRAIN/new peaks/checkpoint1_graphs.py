#-------------------plot Graph machine vs time-----------------
import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib.dates as md
import numpy as np

from datetime import datetime


def create_folder(dirName):
    parent_dir = os.getcwd()
    path = os.path.join(parent_dir, dirName)
    # Create target Directory if don't exist
    if not os.path.exists(dirName):
        os.mkdir(dirName, 0o777)
        print("Directory ", dirName, " Created ")
    else:
        print("Directory ", dirName, " already exists")
    print(path)
    return path


selectedFiles = pd.read_csv("selected files for checkpoint1.csv")
#----------create folders
maliciousDayPath=create_folder("checkponit1 Malicious")
cleanDayPath=create_folder("checkponit1 Clean")
for i in range(len(selectedFiles)):
    #---------plot day vs machine----------
    plt.figure(figsize=(12, 8))
    days = pd.Series(pd.date_range(start='-01-01-2017', end='2017-01-11', freq='D'))
    dates = [pd.to_datetime(ts) for ts in days]
    a =  selectedFiles.iloc[i]['Day_Array']
    a = map(int, list(a[1:-1].split()))
    valuesList =  np.array([int(s) for s in a])
    valuesList = [ts for ts in valuesList]
    plt.subplots_adjust(bottom=0.25)
    plt.xticks(rotation=35)
    ax = plt.gca()
    xfmt = md.DateFormatter('%d-%m-%Y')
    ax.xaxis.set_major_formatter(xfmt)
    ax.xaxis.set_major_locator(plt.MaxNLocator(11))
    plt.plot(dates, valuesList, "o-")
    # rangeCount = range(min(daySet[i]['DailyMachineCount']), max(daySet[i]['DailyMachineCount']) + 1)
    # plt.yticks(rangeCount)
    plt.title("file {0}: Machine per Day".format(selectedFiles.iloc[i]["Sha1ID"]))
    plt.ylabel('Machines')
    plt.xlabel('Days')
    # ax.set_xlim(xmin=min(DaysDeltas))
    ax.set_ylim(ymin=0)
    plt.tick_params(axis='x', which='major', labelsize=7)
    plt.tight_layout()
    plt.grid(b=True, which='major', color='#666666', linestyle='-')
    plt.minorticks_on()
    plt.grid(b=True, which='minor', color='#999999', linestyle='-', alpha=0.2)

   #  #-----------saves day graph------
    if (selectedFiles.iloc[i]["Malicious"]==True):
        path = os.path.join(maliciousDayPath, "file {0}.png".format(selectedFiles.iloc[i]["Sha1ID"]))
        plt.savefig(path)
    else:
           path = os.path.join(cleanDayPath, "file {0}.png".format(selectedFiles.iloc[i]["Sha1ID"]))
           plt.savefig(path)
    plt.clf()
    plt.close()
    # plt.savefig(path)
   # plt.show()

#-------------saves malicious data csv  in maliciousDay and clean data csv in cleanDay ---------




print("finished")
