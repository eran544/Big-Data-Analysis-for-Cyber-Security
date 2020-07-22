import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib.dates as md
from datetime import datetime

dateTimeObj = datetime.now()
starttimestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")
print('START Timestamp : ', starttimestampStr)

# Gets ""daySet.csv"- all files day dataset
# Returns "day Malicious" and "day Clean" folders that contain graphs and "malicious files day data.csv" , "clean files day data.csv"

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

#----------create folders
#
# maliciousDayPath=create_folder("day Malicious")
# cleanDayPath=create_folder("day Clean")

daySet1 = pd.read_csv("daySet.csv",header=0)[["ReportTime", "Sha1ID", "Malicious",
                                              "DailyMachineCount", "MoreThan5", "Size"]]
i = -1
j = 0
currF = daySet1.iloc[0][1]
daySet = [[]]
daySet[j] = []
for sha in daySet1["Sha1ID"]:
    # if i > 269999:
    #     break
    if i%5000 == 0:
        print(i)
    i = i + 1
    if currF == sha:
        daySet[j].append(
            [daySet1.iloc[i][0], daySet1.iloc[i][1], daySet1.iloc[i][2], daySet1.iloc[i][3], daySet1.iloc[i][4], daySet1.iloc[i][5]]
        )
    else:
        daySet[j] = pd.DataFrame(daySet[j], columns=["ReportTime", "Sha1ID", "Malicious",
                                                     "DailyMachineCount", "MoreThan5", "Size"])
        daySet[j]['ReportTime'] = pd.to_datetime(daySet[j]['ReportTime'],dayfirst=True)
        currF = sha
        j = j + 1
        daySet.append([])
        daySet[j].append(
            [daySet1.iloc[i][0], daySet1.iloc[i][1], daySet1.iloc[i][2], daySet1.iloc[i][3], daySet1.iloc[i][4], daySet1.iloc[i][5]])

daySet[j] = pd.DataFrame(daySet[j], columns=["ReportTime", "Sha1ID", "Malicious",
                                             "DailyMachineCount", "MoreThan5", "Size"])
daySet[j]['ReportTime'] = pd.to_datetime(daySet[j]['ReportTime'], dayfirst=True)

numfiles = len(daySet)
print(numfiles)


#------get time set of all hours between 1/1 to 11/1 vs number of machines.------------
DaysDeltas = pd.Series(pd.date_range(start='2017-01-12', end='2017-01-14', freq='D'))
DayDeltasList = [[day,0,] for day in DaysDeltas]
dayRangeVSmachine = []

#------data frames that wii contain all the data about the relevent files. in the end will export to csv.------------
malicious_files = pd.DataFrame([], columns=["Sha1ID","MoreThan5","Malicious",
                                            "Day_Array","Hour_Array","Mean","Std","Size"])
clean_files = pd.DataFrame([], columns=["Sha1ID","MoreThan5","Malicious",
                                        "Day_Array","Hour_Array","Mean","Std","Size"])

#----------create folders
# maliciousDayPath=create_folder("Day Malicious")
# cleanDayPath=create_folder("Day Clean")

for i in range(numfiles):
    if i%5000 == 0:
        print(i)

    # ------data about file i----
    fileSha=daySet[i]["Sha1ID"][0]
    more_than5 = daySet[i]["MoreThan5"][0]
    Malicious = daySet[i]["Malicious"][0]
    size = daySet[i]["Size"][0]
    #----ranged by day----
    dayRangeVSmachine.append(pd.DataFrame(DayDeltasList, columns=['ReportTime', 'DailyMachineCount']))
    dayRangeVSmachine[i] = daySet[i].append(dayRangeVSmachine[i], ignore_index=True)
    dayRangeVSmachine[i].drop_duplicates('ReportTime', keep="first", inplace=True)
    dayRangeVSmachine[i].sort_values(by=['ReportTime'], ascending=[True], inplace=True)
    dayRangeVSmachine[i]["Sha1ID"] = fileSha
    dayRangeVSmachine[i]["MoreThan5"] = more_than5
    dayRangeVSmachine[i]["Malicious"] = Malicious
    dayRangeVSmachine[i]["Size"] = size
    day_Array=dayRangeVSmachine[i]["DailyMachineCount"].to_numpy()

    # --------- statistics---------
    # Average per day
    mean = dayRangeVSmachine[i]["DailyMachineCount"].mean()
    daySet[i]['Mean'] = mean
    #print("file {}: Average machine count per day is: {:.3f}".format(fileSha, perDayAverageMachine))
    # Std
    std = dayRangeVSmachine[i]["DailyMachineCount"].std()
    daySet[i]['Std'] = std
    #print("file {}: Standard deviation is: {:.3f}".format(fileSha, fileStd))

    # --------- data line---------
    data_for_file = pd.DataFrame([[fileSha, more_than5, Malicious, day_Array, mean, std, size]],
                                 columns=["Sha1ID","MoreThan5","Malicious","Day_Array","Mean","Std","Size"])


#-------------------plot Graph machine vs time-----------------

   #  # ---------plot day vs machine----------
   #  plt.figure(figsize=(12, 8))
   #  days = daySet[i]['ReportTime']
   #  dates = [pd.to_datetime(ts) for ts in days]
   #  values = daySet[i]['DailyMachineCount']
   #  valuesList = [ts for ts in values]
   #  plt.subplots_adjust(bottom=0.25)
   #  plt.xticks(rotation=35)
   #  ax = plt.gca()
   #  xfmt = md.DateFormatter('%d-%m-%Y')
   #  ax.xaxis.set_major_formatter(xfmt)
   #  ax.xaxis.set_major_locator(plt.MaxNLocator(11))
   #  plt.plot(dates, valuesList, "o-")
   #  rangeCount = range(min(daySet[i]['DailyMachineCount']), max(daySet[i]['DailyMachineCount']) + 1)
   #  plt.yticks(rangeCount)
   #  plt.title("file {0}: Machine per Day".format(fileSha))
   #  plt.ylabel('Machines')
   #  plt.xlabel('Days')
   #  ax.set_xlim(xmin=min(DaysDeltas))
   #  ax.set_ylim(ymin=0)
   #  plt.tick_params(axis='x', which='major', labelsize=7)
   #  plt.tight_layout()
   #  plt.grid(b=True, which='major', color='#666666', linestyle='-')
   #  plt.minorticks_on()
   #  plt.grid(b=True, which='minor', color='#999999', linestyle='-', alpha=0.2)
   #
   #  #-----------saves day graph------
    if (Malicious):
   #      path = os.path.join(maliciousDayPath, "file {0}.png".format(fileSha))
        if (more_than5):
            malicious_files=malicious_files.append(data_for_file, ignore_index=True)
        #print("A")
   #      plt.savefig(path)
    else:
        if (more_than5):
   #         path = os.path.join(cleanDayPath, "file {0}.png".format(fileSha))
           clean_files = clean_files.append(data_for_file, ignore_index=True)
   #         plt.savefig(path)
   #  plt.clf()
   #  plt.close()
   #  # plt.savefig(path)
   # # plt.show()

#-------------saves malicious data csv  in maliciousDay and clean data csv in cleanDay ---------
parent_dir = os.getcwd()
malicious_files.to_csv(os.path.join(parent_dir, "Malicious Files Day Data.csv"))
clean_files.to_csv(os.path.join(parent_dir, "Clean Files Day Data.csv"))


print("END day")
fileML = open('Dayset_to_day_data timestamp.txt', "a+")  # append mode
fileML.write('START Timestamp : '+ starttimestampStr )
parent_dir = os.getcwd()
dateTimeObj = datetime.now()
timestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")
print(',END Timestamp : ', timestampStr)
fileML.write    ('END Timestamp : '+ timestampStr)
fileML.write('\n ----------- \n')
fileML.close()

print("finished")
# # save file
# path=create_folder("hourSet Filse")
# # hourSet[i].to_csv(path)
# daySet[i].to_csv('daySet file {0}.csv'.format(hourSet[i]["Sha1ID"][0]))
#
# hourSet[i].to_csv('hourSet file {0}.csv'.format(hourSet[i]["Sha1ID"][0]))
# # Make sure you don’t exclude them in the analysis! (as they are prevalent)
