import pandas as pd
import matplotlib.dates as md
import matplotlib.pyplot as plt

#TODO: add fileSha to every file
fileSha = 1103026
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

#--------------------create a dataSet to a speceific file------------------------------
day1.sort_values(by=['Sha1ID', 'ReportTime'], ascending=[True, True], inplace=True)
oneMachine = day1.loc[day1['Sha1ID'] == fileSha]
files = []
files.append(oneMachine)
files[0] = pd.DataFrame(files[0])
files[0].rename(columns={"ReportTime": "time", "MachineGuidID": "machine"}, inplace=True, errors="raise")

#------------------remove from each dataSet file apearnces with duplicated machines and keep the earliest-----------
i = 0
for i in range(len(files)):
    files[i].sort_values(by=['time', 'machine'], ascending=[True, True], inplace=True)
    files[i].drop_duplicates('machine', keep="first", inplace=True)


#-------------------create time set to each file dataset - machine vs hours-----------------
#------------hourSet - hour vs machine----------------
i = 0
hourSet = []
for i in range(len(files)):
    if (i == 13):
        print("fg")
    files[i]['time'] = pd.to_datetime(files[i]['time'])
    hourSet.append(files[i].groupby([pd.Grouper(key='time', freq='H')]).size().reset_index(name='count'))
#------------ daySet-day vs machine-----------------
i = 0
daySet = []
for i in range(len(files)):
    if (i == 13):
        print("fg")
    files[i]['time'] = pd.to_datetime(files[i]['time'])
    daySet.append(files[i].groupby([pd.Grouper(key='time', freq='D')]).size().reset_index(name='count'))


#------get time set of all hours between 1/1 to 11/1 vs number of machines.------------
#------ranged by hour----
HourDeltas = pd.Series(pd.date_range(start='2017-01-01', end='2017-01-12', freq='H'))
HourDeltasList = [[hour,0] for hour in HourDeltas]
hourRangeVSmachine = []

for i in range(len(files)):
    hourRangeVSmachine.append(pd.DataFrame(HourDeltasList, columns=['time', 'count']))
    hourRangeVSmachine[i] = hourSet[i].append(hourRangeVSmachine[i], ignore_index=True)
    hourRangeVSmachine[i].drop_duplicates('time', keep="first", inplace=True)
    hourRangeVSmachine[i].sort_values(by=['time'], ascending=[True], inplace=True)

#----ranged by day----
DaysDeltas = pd.Series(pd.date_range(start='2017-01-01', end='2017-01-12', freq='D'))
DayDeltasList = [[day,0] for day in DaysDeltas]
dayRangeVSmachine = []
for i in range(len(files)):
    dayRangeVSmachine.append(pd.DataFrame(DayDeltasList, columns=['time', 'count']))
    dayRangeVSmachine[i] = daySet[i].append(dayRangeVSmachine[i], ignore_index=True)
    dayRangeVSmachine[i].drop_duplicates('time', keep="first", inplace=True)
    dayRangeVSmachine[i].sort_values(by=['time'], ascending=[True], inplace=True)

#-------------------plot Graph machine vs time-----------------

# i = 0
# for i in range(len(hourSet)):
    # ---------plot hour vs machine----------
    plt.figure(figsize=(12, 8))
    hours = hourSet[i]['time']
    dates = [pd.to_datetime(ts) for ts in hours]
    values = hourSet[i]['count']
    valuesList = [ts for ts in values]
    plt.subplots_adjust(bottom=0.25)
    plt.xticks(rotation=50)
    ax = plt.gca()
    xfmt = md.DateFormatter('%d-%m-%Y\n%H:%M:%S')
    ax.xaxis.set_major_formatter(xfmt)
    ax.xaxis.set_major_locator(plt.MaxNLocator(22))
    plt.gca().xaxis.set_minor_locator(md.HourLocator())
    plt.plot(dates, valuesList, "o-")
    rangeCount = range(min(hourSet[i]['count']), max(hourSet[i]['count']) + 1)
    plt.yticks(rangeCount)
    plt.title("file {0}: Machine per Hour".format(fileSha))
    plt.ylabel('Machines')
    plt.xlabel('Hours')
    ax.set_xlim(xmin=min(HourDeltas))
    ax.set_ylim(ymin=0)
    plt.tick_params(axis='x', which='major', labelsize=7)
    plt.tight_layout()
    plt.grid(b=True, which='major', color='#666666', linestyle='-')
    plt.minorticks_on()
    plt.grid(b=True, which='minor', color='#999999', linestyle='-', alpha=0.2)
    plt.show()
#for i in range(len(daySet)):
    # ---------plot day vs machine----------
    plt.figure(figsize=(12, 8))
    days = daySet[i]['time']
    dates = [pd.to_datetime(ts) for ts in days]
    values = daySet[i]['count']
    valuesList = [ts for ts in values]
    plt.subplots_adjust(bottom=0.25)
    plt.xticks(rotation=35)
    ax = plt.gca()
    xfmt = md.DateFormatter('%d-%m-%Y')
    ax.xaxis.set_major_formatter(xfmt)
    ax.xaxis.set_major_locator(plt.MaxNLocator(11))
    plt.plot(dates, valuesList, "o-")
    rangeCount = range(min(daySet[i]['count']), max(daySet[i]['count']) + 1)
    plt.yticks(rangeCount)
    plt.title("file {0}: Machine per Day".format(fileSha))
    plt.ylabel('Machines')
    plt.xlabel('Days')
    ax.set_xlim(xmin=min(DaysDeltas))
    ax.set_ylim(ymin=0)
    plt.tick_params(axis='x', which='major', labelsize=7)
    plt.tight_layout()
    plt.grid(b=True, which='major', color='#666666', linestyle='-')
    plt.minorticks_on()
    plt.grid(b=True, which='minor', color='#999999', linestyle='-', alpha=0.2)
    plt.show()

#---------plot statistics----------
# what is the average count per day?
# What is the standard deviation?
# What is the difference between the daily and the hourly scale?
# Which one should be used? Etc.
# Include in your report some TS graphs and statistics from the analysis you perform and describe any insights you gained.

    #Average per day
    perDayAverageMachine = dayRangeVSmachine[i].mean()
    print("file {}: Average machine count per day is: {:.3f}".format(fileSha, perDayAverageMachine[i]))
    # Std
    fileStd = dayRangeVSmachine[i].std()
    print("file {}: Standard deviation is: {:.3f}".format(fileSha, fileStd[i]))