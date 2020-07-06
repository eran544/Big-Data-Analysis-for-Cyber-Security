import pandas as pd
import os
import matplotlib.dates as md
import matplotlib.pyplot as plt
import pickle
from datetime import datetime
#Gets "data.csv" - all data given to us
#filters it by day and by hour
# creates 'daySet.csv' 'hourSet.csv'

dateTimeObj = datetime.now()
starttimestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")
print('START Timestamp : ', starttimestampStr)

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




def create_dataset():
    allData = pd.read_csv("data.csv")[
        ["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID", "Size"
        ]]  # keep relavent coulmns #dataframe
    files = [[]]
    # --------------------create a dataSet to each file------------------------------
    allData.sort_values(by=['Sha1ID', 'ReportTime'], ascending=[True, True], inplace=True)
    i = -1
    j = 0
    currF = allData.iloc[0][0]
    #files = [[]]
    files[j] = []
    for sha in allData["Sha1ID"]:
        if i%5000 == 0: #TODO check
            print(i)
        if sha==15201105:
            print("A")
        i = i + 1
        if currF == sha:
            files[j].append(
                [allData.iloc[i][0], allData.iloc[i][1], allData.iloc[i][2], allData.iloc[i][3], allData.iloc[i][4]])
        else:
            files[j] = pd.DataFrame(files[j], columns=["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID", "Size"])
            currF = sha
            j = j + 1
            files.append([])
            files[j].append(
                [allData.iloc[i][0], allData.iloc[i][1], allData.iloc[i][2], allData.iloc[i][3], allData.iloc[i][4]])
    files[j] = pd.DataFrame(files[j], columns=["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID", "Size"])
    return files

    #del allData
    #gc.collect()


def sortByMachines(files):
# ------------------remove from each dataSet file apearnces with duplicated machines and keep the earliest-----------
    i = 0
    hourSet = []
    daySet = []
    for i in range(len(files)):
        if i%5000 == 0: #TODO check
            print(i)
        if i == 423:
            print("A")
        # add label malicious
        if ((files[i].ThreatNameID.values != 5644).sum() > 0):
            files[i]['Malicious'] = True
        else:
            files[i]['Malicious'] = False
        files[i].sort_values(by=['ReportTime', 'MachineGuidID'], ascending=[True, True], inplace=True)

        # -------------------create time set to each file dataset - machine vs hours-----------------
        # ------------hourSet - hour vs machine----------------
        # files[i]['ReportTime'] = pd.to_datetime(files[i]['ReportTime']).apply(lambda x: x.replace(minute=0, second=0))
        # files[i].drop_duplicates(('MachineGuidID' ,'ReportTime'), keep="first", inplace=True)
        #
        #
        # hourSet.append(files[i].groupby([pd.Grouper(key='ReportTime', freq='H'), "Sha1ID", "Malicious", "Size"]).size().reset_index(
        #         name='HourlyMachineCount'))
        # # Clean-Prevalent file (more than X machines)
        # if (hourSet[i]['HourlyMachineCount'].sum() > 10):
        #     hourSet[i]['MoreThan10'] = True
        # else:
        #     hourSet[i]['MoreThan10'] = False


        # ------------ daySet-day vs machine-----------------
        files[i]['ReportTime'] = pd.to_datetime(files[i]['ReportTime']).apply(
lambda x: x.replace(hour=0, minute=0, second=0))
        files[i].drop_duplicates(('MachineGuidID', 'ReportTime'), keep="first", inplace=True)

        daySet.append(files[i].groupby([pd.Grouper(key='ReportTime', freq='D'), "Sha1ID", "Malicious", "Size"]).size().reset_index(
            name='DailyMachineCount'))

        # Clean-Prevalent file (more than X machines)
        if (daySet[i]['DailyMachineCount'].sum() > 10):
            daySet[i]['MoreThan10'] = True
        else:
            daySet[i]['MoreThan10'] = False

    return (daySet,hourSet,len(files))

 #-------------got from pre function ----------


files = create_dataset()
# with open('FILES.pkl', 'wb') as f:
#     pickle.dump(files, f)

(daySet,hourSet,numfiles)=sortByMachines(create_dataset())
print("dataset created")

pd.concat(daySet).to_csv('daySet.csv')
# pd.concat(hourSet).to_csv('hourSet.csv')

fileML = open("All_data_to_Hour_Day_datasets timestamp", "a+")  # append mode
fileML.write('START Timestamp : '+ starttimestampStr )
parent_dir = os.getcwd()
dateTimeObj = datetime.now()
timestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")
print(',END Timestamp : ', timestampStr)
fileML.write('END Timestamp : '+ timestampStr)
fileML.write('\n ----------- \n')
fileML.close()

print("saved")



