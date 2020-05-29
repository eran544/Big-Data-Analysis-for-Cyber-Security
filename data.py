import dates as dates
import pandas as pd
import matplotlib.pyplot as plt
import glob
import pandas as pd
import datetime as dt
import time
import matplotlib.dates as md
import numpy as np
import dateutil


#-------------------import csv from path -------------------------
from datetime import datetime
# # get data file names
# path =r'C:\Users\user\Documents\לימודים\שנה ד\סמסטר ב\Big Data Analysis for Cyber Security'
# filenames = glob.glob(path + "/*.csv")
#
# dfs = []
# for filename in filenames:
#     dfs.append(pd.read_csv(filename))
#
# # Concatenate all data into one DataFrame
# big_frame = pd.concat(dfs, ignore_index=True)
# print ("a")
from matplotlib import pyplot, rcParams

day = pd.read_csv("data.csv")
day1 = day[["Sha1ID", "FileNameId", "ReportTime", "MachineGuidID"]]

#--------------------create a dataSet to each file------------------------------
# day1.sort_values(by=['Sha1ID', 'ReportTime'], ascending=[True, True], inplace=True)
# i = -1
# j = 0
# currF = day1.iloc[0][0]
# files = [[]]
# files[j] = []
# for sha in day1["Sha1ID"]:
#     if i < 500:
#         i = i + 1
#         if currF == sha:
#             files[j].append(
#                 [day1.iloc[i][0], day1.iloc[i][1], day1.iloc[i][2], day1.iloc[i][3]]
#             )
#         else:
#             files[j] = pd.DataFrame(files[j], columns=["sha", "name", "time", "machine"])
#             currF = sha
#             j = j + 1
#             files.append([])
#             files[j].append(
#                 [day1.iloc[i][0], day1.iloc[i][1], day1.iloc[i][2], day1.iloc[i][3]]
#             )
# files[j] = pd.DataFrame(files[j], columns=["sha", "name", "time", "machine"])
#--------------------create a dataSet to a specific file------------------------------
day1.sort_values(by=['Sha1ID', 'ReportTime'], ascending=[True, True], inplace=True)
oneMechine = day1.loc[day1['Sha1ID'] == 5323043]
files=[]
files.append(oneMechine)
files[0] = pd.DataFrame(files[0])
files[0].rename(columns={"ReportTime": "time", "MachineGuidID": "machine"}, inplace=True, errors="raise")

#------------------remove from each dataSet file apearnces with duplicated machines and keep the earliest-----------
i = 0
for i in range(len(files)):
    files[i].sort_values(by=['time', 'machine'], ascending=[True, True], inplace=True)
    files[i].drop_duplicates('machine', keep="first", inplace=True)


#-------------------create time set to each file dataset - machine vs hours-----------------
i = 0
timeSets = []
for i in range(len(files)):
    if (i==13):
        print("fg")
    files[i]['time'] = pd.to_datetime(files[i]['time'])
    timeSets.append(files[i].groupby([pd.Grouper(key='time',freq='H')]).size().reset_index(name='count'))
print("A")

#------get time set of all hours between 1/1 to 11/1 vs number of machines.------------
#ranged by hour
HourDeltas = pd.Series(pd.date_range(start='2017-01-01', end='2017-01-12', freq='H'))
HourDeltasList = [[hour,0] for hour in HourDeltas]
timeRangeVSmacine=[]

for i in range(len(files)):
    timeRangeVSmacine.append(pd.DataFrame(HourDeltasList, columns=['time', 'count']))
    timeRangeVSmacine[i]=timeSets[i].append(timeRangeVSmacine[i],ignore_index=True)
    timeRangeVSmacine[i].drop_duplicates('time', keep="first", inplace=True)
    timeRangeVSmacine[i].sort_values(by=['time'], ascending=[True], inplace=True)

#-------------------print Graph machine vs hours-----------------

i = 0
for i in range(len(timeSets)):
    plt.figure(figsize=(12, 6))

    hours = timeSets[i]['time']
    dates = [pd.to_datetime(ts) for ts in hours]
    values = timeSets[i]['count']
    valuesList = [ts for ts in values]
    plt.subplots_adjust(bottom=0.1)
    plt.xticks(rotation=50)
    ax = plt.gca()
    xfmt = md.DateFormatter('%Y-%m-%d\n%H:%M:%S')
    ax.xaxis.set_major_formatter(xfmt)
    ax.xaxis.set_major_locator(plt.MaxNLocator(22))
    plt.gca().xaxis.set_minor_locator(md.HourLocator())
    plt.plot(dates, valuesList, "o-")
    print("x")
    rangeCount = range(min(timeSets[i]['count']),max(timeSets[i]['count'])+1)
    plt.yticks(rangeCount)
    plt.title("file {0}".format(i))
    plt.ylabel('machines')
    plt.xlabel('hours')

    ax.set_xlim(xmin=min(HourDeltas))
    ax.set_ylim(ymin=0)
    plt.tick_params(axis='x', which='major', labelsize=7)
    plt.tight_layout()
    plt.grid(b=True, which='major', color='#666666', linestyle='-')
    plt.minorticks_on()
    plt.grid(b=True, which='minor', color='#999999', linestyle='-', alpha=0.2)

    plt.show()

#-------------------