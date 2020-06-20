import pickle
with open('FILES.pkl', 'rb') as f:
    files = pickle.load(f)

import pandas as pd
import os
import matplotlib.dates as md
import matplotlib.pyplot as plt
import gc
import json
#Gets "data.csv" - all data given to us
#filters it by day and by hour
# creates 'daySet.csv' 'hourSet.csv'

# allData = pd.read_csv("allData.csv")[
#     ["Sha1ID", "ThreatNameID", "ReportTime", "MachineGuidID", "Size"]]  # keep relavent coulmns #dataframe

def sortByMachines(files):
# ------------------remove from each dataSet file apearnces with duplicated machines and keep the earliest-----------
    i = 0
    hourSet = []
    daySet = []
    for i in range(len(files)):
        if i%5000 == 0: #TODO check
            print(i)
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
        hourSet.append(files[i].groupby([pd.Grouper(key='ReportTime', freq='H'), "Sha1ID", "Malicious", "Size"]).size().reset_index(
                name='HourlyMachineCount'))
        # Clean-Prevalent file (more than X machines)
        if (hourSet[i]['HourlyMachineCount'].sum() > 100):
            hourSet[i]['MoreThan100'] = True
        else:
            hourSet[i]['MoreThan100'] = False


        # ------------ daySet-day vs machine-----------------
        daySet.append(files[i].groupby([pd.Grouper(key='ReportTime', freq='D'), "Sha1ID", "Malicious", "Size"]).size().reset_index(
            name='DailyMachineCount'))

        # Clean-Prevalent file (more than X machines)
        if (daySet[i]['DailyMachineCount'].sum() > 100):
            daySet[i]['MoreThan100'] = True
        else:
            daySet[i]['MoreThan100'] = False

    return (daySet,hourSet,len(files))

 #-------------got from pre function ----------
(daySet,hourSet,numfiles)=sortByMachines(files)
print("dataset created")

pd.concat(daySet).to_csv('daySet.csv')
pd.concat(hourSet).to_csv('hourSet.csv')

print("saved")



