import pandas as pd
import os
import matplotlib.dates as md
import matplotlib.pyplot as plt

def create_folder(dirName):
    parent_dir = os.getcwd()
    path = os.path.join(parent_dir, dirName)
    # Create target Directory if don't exist
    if not os.path.exists(dirName):
        os.mkdir(dirName, 0o777)
        print("Directory ", dirName, " Created ")
    else:
        print("Directory ", dirName, " already exists")
    return path

def create_dataset():
    allData = pd.read_csv("data.csv")[
        ["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID"]]  # keep relevent coulms #dataframe

    # --------------------create a dataSet to each file------------------------------
    allData.sort_values(by=['Sha1ID', 'ReportTime'], ascending=[True, True], inplace=True)
    i = -1
    j = 0
    currF = allData.iloc[0][0]
    files = [[]]
    files[j] = []
    for sha in allData["Sha1ID"]:
        if i < 100:
            i = i + 1
            if currF == sha:
                files[j].append(
                    [allData.iloc[i][0], allData.iloc[i][1], allData.iloc[i][2], allData.iloc[i][3]]
                )
            else:
                files[j] = pd.DataFrame(files[j], columns=["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID"])
                currF = sha
                j = j + 1
                files.append([])
                files[j].append(
                    [allData.iloc[i][0], allData.iloc[i][1], allData.iloc[i][2], allData.iloc[i][3]]
                )
    files[j] = pd.DataFrame(files[j], columns=["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID"])
    return files

def sortByMachines(files):
# ------------------remove from each dataSet file apearnces with duplicated machines and keep the earliest-----------
    i = 0
    hourSet = []
    daySet = []
    for i in range(len(files)):
        # add label malicious
        if ((files[i].ThreatNameID.values != 5644).sum() > 0):
            files[i]['Malicious'] = True
        else:
            files[i]['Malicious'] = False
        files[i].sort_values(by=['ReportTime', 'MachineGuidID'], ascending=[True, True], inplace=True)
        files[i].drop_duplicates('MachineGuidID', keep="first", inplace=True)

        # -------------------create time set to each file dataset - machine vs hours-----------------
        files[i]['ReportTime'] = pd.to_datetime(files[i]['ReportTime'])
        # ------------hourSet - hour vs machine----------------
        hourSet.append(files[i].groupby([pd.Grouper(key='ReportTime', freq='H'), "Sha1ID", "Malicious"]).size().reset_index(
                name='HourlyMachineCount'))
        # Clean-Prevalent file (more than X machines)
        if (hourSet[i]['HourlyMachineCount'].sum() > 100):
            hourSet[i]['MoreThan100'] = True
        else:
            hourSet[i]['MoreThan100'] = False


        # ------------ daySet-day vs machine-----------------
        daySet.append(files[i].groupby([pd.Grouper(key='ReportTime', freq='D'), "Sha1ID", "Malicious"]).size().reset_index(
            name='DailyMachineCount'))

        # Clean-Prevalent file (more than X machines)
        if (daySet[i]['DailyMachineCount'].sum() > 100):
            daySet[i]['MoreThan100'] = True
        else:
            daySet[i]['MoreThan100'] = False

    return (daySet,hourSet,len(files))


# #-------------seperate files ----------
# "DailyMachineCount",  "HourlyMachineCount"," MoreThan100"," Malicious" Sha1ID
(daySet,hourSet,numfiles)=sortByMachines(create_dataset())



#------get time set of all hours between 1/1 to 11/1 vs number of machines.------------
HourDeltas = pd.Series(pd.date_range(start='2017-01-01', end='2017-01-12', freq='H'))
hourRangeVSmachine = []
DaysDeltas = pd.Series(pd.date_range(start='2017-01-01', end='2017-01-12', freq='D'))
DayDeltasList = [[day,0,] for day in DaysDeltas]
dayRangeVSmachine = []
#----------create folders
maliciousDayPath=create_folder("day Malicious")
cleanDayPath=create_folder("day Clean")
maliciousHourPath=create_folder("Hour Malicious")
cleanHourPath=create_folder("Hour Clean")

for i in range(numfiles):
    # "DailyMachineCount",  "HourlyMachineCount"," MoreThan100"," Malicious"
    fileSha=daySet[i]["Sha1ID"][0]
    MoreThan100 = daySet[i]["MoreThan100"][0]
    Malicious = daySet[i]["Malicious"][0]
    # ------ranged by hour----
    HourDeltasList = [[hour, 0] for hour in HourDeltas]
    hourRangeVSmachine.append(pd.DataFrame(HourDeltasList, columns=["ReportTime", 'HourlyMachineCount']))
    hourRangeVSmachine[i] = hourSet[i].append(hourRangeVSmachine[i], ignore_index=True)
    hourRangeVSmachine[i].drop_duplicates('ReportTime', keep="first", inplace=True)
    hourRangeVSmachine[i].sort_values(by=['ReportTime'], ascending=[True], inplace=True)
    hourRangeVSmachine[i]["Sha1ID"]=fileSha
    hourRangeVSmachine[i]["MoreThan100"] = MoreThan100
    hourRangeVSmachine[i]["Malicious"] = Malicious
    #----ranged by day----
    dayRangeVSmachine.append(pd.DataFrame(DayDeltasList, columns=['ReportTime', 'DailyMachineCount']))
    dayRangeVSmachine[i] = daySet[i].append(dayRangeVSmachine[i], ignore_index=True)
    dayRangeVSmachine[i].drop_duplicates('ReportTime', keep="first", inplace=True)
    dayRangeVSmachine[i].sort_values(by=['ReportTime'], ascending=[True], inplace=True)
    dayRangeVSmachine[i]["Sha1ID"] = fileSha
    dayRangeVSmachine[i]["MoreThan100"] = MoreThan100
    dayRangeVSmachine[i]["Malicious"] = Malicious

#TODO:fix gragh
#-------------------plot Graph machine vs time-----------------
    # ---------plot hour vs machine----------
    plt.figure(figsize=(12, 6))
    hours = hourSet[i]['ReportTime']
    dates = [pd.to_datetime(ts) for ts in hours]
    values = hourSet[i]['HourlyMachineCount']
    valuesList = [ts for ts in values]

    plt.subplots_adjust(bottom=0.25)
    plt.xticks(rotation=50)
    ax = plt.gca()
    xfmt = md.DateFormatter('%d-%m-%Y\n%H:%M:%S')
    ax.xaxis.set_major_formatter(xfmt)
    ax.xaxis.set_major_locator(plt.MaxNLocator(22))
   # plt.gca().xaxis.set_minor_locator(md.HourLocator())
    plt.plot(dates, valuesList, "o-")
    rangeCount = range(min(hourSet[i]['HourlyMachineCount']), max(hourSet[i]['HourlyMachineCount']) + 1)
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
    #fig = plt.figure()


    if (Malicious):
        path = os.path.join(maliciousHourPath, "file {0}.png".format(fileSha))
    #else if(MoreThan100): #TODO
    else:
        path = os.path.join(cleanHourPath, "file {0}.png".format(fileSha))
    plt.savefig(path)
    #plt.show()

    # ---------plot day vs machine----------
    plt.figure(figsize=(12, 8))
    days = daySet[i]['ReportTime']
    dates = [pd.to_datetime(ts) for ts in days]
    values = daySet[i]['DailyMachineCount']
    valuesList = [ts for ts in values]
    plt.subplots_adjust(bottom=0.25)
    plt.xticks(rotation=35)
    ax = plt.gca()
    xfmt = md.DateFormatter('%d-%m-%Y')
    ax.xaxis.set_major_formatter(xfmt)
    ax.xaxis.set_major_locator(plt.MaxNLocator(11))
    plt.plot(dates, valuesList, "o-")
    rangeCount = range(min(daySet[i]['DailyMachineCount']), max(daySet[i]['DailyMachineCount']) + 1)
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


    if (Malicious):
        path = os.path.join(maliciousDayPath, "file {0}.png".format(fileSha))
        # else if(MoreThan100): #TODO
    else:
        path = os.path.join(cleanDayPath, "file {0}.png".format(fileSha))

    plt.savefig(path)
   # plt.show()
    #---------plot statistics----------
    # what is the average count per day?
    # What is the standard deviation?
    # What is the difference between the daily and the hourly scale?
    # Which one should be used? Etc.
    # Include in your report some TS graphs and statistics from the analysis you perform and describe any insights you gained.

    #Average per day
    perDayAverageMachine = dayRangeVSmachine[i]["DailyMachineCount"].mean()
    daySet[i]['mean'] = perDayAverageMachine
    print("file {}: Average machine count per day is: {:.3f}".format(fileSha, perDayAverageMachine))
    # Std
    fileStd = dayRangeVSmachine[i]["DailyMachineCount"].std()
    daySet[i]['std'] = perDayAverageMachine
    print("file {}: Standard deviation is: {:.3f}".format(fileSha, fileStd))
#-------------save---------

print("A")
# # save file
# path=create_folder("hourSet Filse")
# hourSet[i].to_csv(path)
# daySet[i].to_csv('daySet file {0}.csv'.format(hourSet[i]["Sha1ID"][0]))

# hourSet[i].to_csv('hourSet file {0}.csv'.format(hourSet[i]["Sha1ID"][0]))
# Make sure you don’t exclude them in the analysis! (as they are prevalent)