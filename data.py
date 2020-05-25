import dates as dates
import pandas as pd
import matplotlib.pyplot as plt
import glob
import pandas as pd

# get data file names
path =r'C:\Users\user\Documents\לימודים\שנה ד\סמסטר ב\Big Data Analysis for Cyber Security'
filenames = glob.glob(path + "/*.csv")

dfs = []
for filename in filenames:
    dfs.append(pd.read_csv(filename))

# Concatenate all data into one DataFrame
big_frame = pd.concat(dfs, ignore_index=True)
print ("a")

# day = pd.read_csv("data.csv")
# day1 = day[["Sha1ID", "FileNameId", "ReportTime", "MachineGuidID"]]
#
# #create a dataSet to each file
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
#
#
# #remove from each dataSet file apearnces with duplicated machines and keep the earliest
# i = 0
# for i in range(len(files)):
#     files[i].sort_values(by=['time', 'machine'], ascending=[True, True], inplace=True)
#     files[i].drop_duplicates('machine', keep="first", inplace=True)
#
#
# #create time set to each file dataset - machine vs hours
# i = 0
# timeSets = []
# for i in range(len(files)):
#     if (i==13):
#         print("fg")
#     files[i]['time'] = pd.to_datetime(files[i]['time'])
#     timeSets.append(files[i].groupby([pd.Grouper(key='time',freq='H')]).size().reset_index(name='count'))
# print("A")
#
#
#
#
# i = 0
# for i in range(len(timeSets)):
#     plt.plot(timeSets[i]['time'].dt.hour, timeSets[i]['count'], 'ro')
#     hours = range(0, 25)
#     rangeCount = range(min(timeSets[i]['count']),max(timeSets[i]['count'])+1)
#     plt.xticks(hours)
#     plt.yticks(rangeCount)
#     plt.title("file {0}".format(i))
#     plt.ylabel('machines')
#     plt.xlabel('hours')
#
#
#     plt.show()