import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib.dates as md

# Gets "hourSet.csv"- all files hours dataset
# Returns "Hour Malicious" and "Hour Clean" folders that contain graphs and "malicious files hour data.csv" , "clean files hour data.csv"
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
maliciousHourPath=create_folder("Hour Malicious")
cleanHourPath=create_folder("Hour Clean")

hourSet1 = pd.read_csv("hourSet.csv",header=0)[["ReportTime", "Sha1ID", "Malicious", "HourlyMachineCount", "MoreThan10", "Size","WebFileUrlDomain"]]
i = -1
j = 0
currF = hourSet1.iloc[0][1]
hourSet = [[]]
hourSet[j] = []
for sha in hourSet1["Sha1ID"]:
    if i%5000 == 0:
        print(i)
    i = i + 1
    if currF == sha:
        hourSet[j].append(
            [hourSet1.iloc[i][0], hourSet1.iloc[i][1], hourSet1.iloc[i][2], hourSet1.iloc[i][3], hourSet1.iloc[i][4], hourSet1.iloc[i][5], hourSet1.iloc[i][6]]
        )
    else:
        hourSet[j] = pd.DataFrame(hourSet[j], columns=["ReportTime", "Sha1ID", "Malicious", "HourlyMachineCount", "MoreThan10", "Size","WebFileUrlDomain"])
        hourSet[j]['ReportTime'] = pd.to_datetime(hourSet[j]['ReportTime'],dayfirst=True)
        currF = sha
        j = j + 1
        hourSet.append([])
        hourSet[j].append(
            [hourSet1.iloc[i][0], hourSet1.iloc[i][1], hourSet1.iloc[i][2], hourSet1.iloc[i][3], hourSet1.iloc[i][4], hourSet1.iloc[i][5], hourSet1.iloc[i][6]])

hourSet[j] = pd.DataFrame(hourSet[j], columns=["ReportTime", "Sha1ID", "Malicious", "HourlyMachineCount", "MoreThan10", "Size","WebFileUrlDomain"])
hourSet[j]['ReportTime'] = pd.to_datetime(hourSet[j]['ReportTime'], dayfirst=True)

numfiles = len(hourSet)
print(numfiles)


#------get time set of all hours between 1/1 to 11/1 vs number of machines.------------
HourDeltas = pd.Series(pd.date_range(start='2017-01-01', end='2017-01-11 23:00:00', freq='H'))
HourDeltasList = [[hour, 0] for hour in HourDeltas]
hourRangeVSmachine = []

#------data frames that wii contain all the data about the relevent files. in the end will export to csv.------------
malicious_files = pd.DataFrame([], columns=["Sha1ID","MoreThan10","Malicious","Day_Array","Hour_Array","Size","WebFileUrlDomain"])
clean_files = pd.DataFrame([], columns=["Sha1ID","MoreThan10","Malicious","Day_Array","Hour_Array","Size","WebFileUrlDomain"])

#----------create folders
maliciousDayPath=create_folder("hour Malicious")
cleanDayPath=create_folder("hour Clean")

for i in range(numfiles):
    if i%5000 == 0:
        print(i)
    # ------data about file i----
    fileSha=hourSet[i]["Sha1ID"][0]
    MoreThan10 = hourSet[i]["MoreThan10"][0]
    Malicious = hourSet[i]["Malicious"][0]
    Size = hourSet[i]["Size"][0]
    Domain=hourSet[i]["WebFileUrlDomain"][0]

    #----ranged by Hour----
    hourRangeVSmachine.append(pd.DataFrame(HourDeltasList, columns=["ReportTime", 'HourlyMachineCount']))
    hourRangeVSmachine[i] = hourSet[i].append(hourRangeVSmachine[i], ignore_index=True)
    hourRangeVSmachine[i].drop_duplicates('ReportTime', keep="first", inplace=True)
    hourRangeVSmachine[i].sort_values(by=['ReportTime'], ascending=[True], inplace=True)
    hourRangeVSmachine[i]["Sha1ID"]=fileSha
    hourRangeVSmachine[i]["MoreThan10"] = MoreThan10
    hourRangeVSmachine[i]["Malicious"] = Malicious
    hourRangeVSmachine[i]["Size"] = Size
    hourRangeVSmachine[i]["WebFileUrlDomain"] = Domain
    hour_Array=hourRangeVSmachine[i]["HourlyMachineCount"].to_numpy()
    hour_Array = hour_Array.flatten()

    # --------- statistics---------

    # --------- data line---------
    data_for_file = pd.DataFrame([[fileSha,MoreThan10,Malicious,hour_Array, Size,Domain]],columns=["Sha1ID","MoreThan10","Malicious","Hour_Array","Size","WebFileUrlDomain"])


    #-------------------plot Graph machine vs time-----------------

    # ---------plot hour vs machine----------
    # TODO:fix gragh
    #  if(i==numfiles-1):
    #      print("A")
    #  plt.figure(figsize=(12, 6))
    #  hours = hourSet[i]['ReportTime']
    #  dates = [pd.to_datetime(ts) for ts in hours]
    #  values = hourSet[i]['HourlyMachineCount']
    #  valuesList = [ts for ts in values]
    #
    #  plt.subplots_adjust(bottom=0.25)
    #  plt.xticks(rotation=50)
    #  ax = plt.gca()
    #  xfmt = md.DateFormatter('%d-%m-%Y\n%H:%M:%S')
    #  ax.xaxis.set_major_formatter(xfmt)
    #  ax.xaxis.set_major_locator(plt.MaxNLocator(22))
    # # plt.gca().xaxis.set_minor_locator(md.HourLocator())
    #  plt.plot(dates, valuesList, "o-")
    #  rangeCount = range(min(hourSet[i]['HourlyMachineCount']), max(hourSet[i]['HourlyMachineCount']) + 1)
    #  plt.yticks(rangeCount)
    #  plt.title("file {0}: Machine per Hour".format(fileSha))
    #  plt.ylabel('Machines')
    #  plt.xlabel('Hours')
    #  ax.set_xlim(xmin=min(HourDeltas))
    #  ax.set_ylim(ymin=0)
    #  plt.tick_params(axis='x', which='major', labelsize=7)
    #  plt.tight_layout()
    #  plt.grid(b=True, which='major', color='#666666', linestyle='-')
    #  plt.minorticks_on()
    #  plt.grid(b=True, which='minor', color='#999999', linestyle='-', alpha=0.2)
    #  #fig = plt.figure()
    #
    #  #-----------saves hour grap and data
    if (Malicious):
        #      path = os.path.join(maliciousHourPath, "file {0}.png".format(fileSha))
        malicious_files=malicious_files.append(data_for_file, ignore_index=True)
        #      plt.savefig(path)
    else:
        if(MoreThan10):
            #          path = os.path.join(cleanHourPath, "file {0}.png".format(fileSha))
            clean_files= clean_files.append(data_for_file, ignore_index=True)
    #          plt.savefig(path)
    #  plt.clf()
    #  plt.close()
    #plt.show()
#-------------saves malicious data csv  in maliciousDay and clean data csv in cleanDay ---------
malicious_files.to_csv(os.path.join(maliciousHourPath, "Malicious Files Hour Data.csv"))
clean_files.to_csv(os.path.join(cleanHourPath, "Clean Files Hour Data.csv"))


print("END hour")
# # save file
# path=create_folder("hourSet Filse")
# # hourSet[i].to_csv(path)
# hourSet[i].to_csv('hourSet file {0}.csv'.format(hourSet[i]["Sha1ID"][0]))
#
# hourSet[i].to_csv('hourSet file {0}.csv'.format(hourSet[i]["Sha1ID"][0]))
# # Make sure you don’t exclude them in the analysis! (as they are prevalent)
