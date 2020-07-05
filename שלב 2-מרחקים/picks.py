import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
# %matplotlib inline
from matplotlib.ticker import PercentFormatter
import matplotlib.ticker as ticker

# #-------------Get the data-----------
malFile = pd.read_csv('malicious files day data.csv')[["Sha1ID","Day_Array"]]
cleanFile = pd.read_csv('clean files day data.csv')[["Sha1ID","Day_Array"]]

piks = pd.concat([malFile, cleanFile], axis=0, ignore_index=True)
piks.insert(2, 'Peaks',     'default value ')
piks.insert(3, 'Sharp peaks',     'default value ')


# piks.columns = ["Sha1ID","Malicious","Day count Mean","Day count STD","Size"]
#----max,min,Prevalence--
malFile_array = pd.read_csv('malicious files day data.csv')[["Day_Array"]]
cleanFile_array  = pd.read_csv('clean files day data.csv')[["Day_Array"]]
arrays = pd.concat([malFile_array, cleanFile_array], axis=0, ignore_index=True)


for i in range(len(arrays)):
    if piks['Sha1ID'][i]==21191:
        print("A")
    a = arrays["Day_Array"][i]
    a = map(int, list(a[1:-1].split()))
    a = np.array([int(s) for s in a])

    import numpy as np
    from scipy.signal import argrelextrema
    peaks = argrelextrema(a, np.greater,mode='wrap')
    peaks= peaks[0][a[peaks[0]] > 3]
    piks.at[i, 'Peaks'] = len(peaks)
    print(peaks)


    from scipy.signal import find_peaks, peak_prominences
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter
    import matplotlib.ticker as ticker
    # sharp_peaks, _ = find_peaks(a)
    # sharp_peaks= sharp_peaks[0][a[sharp_peaks[0]] > 3]
    prominences = peak_prominences(a, peaks)[0]
    sharp_peaks_over=peaks
    for j in range(len(peaks)-1,-1,-1):
        if prominences[j]<15:
            sharp_peaks_over= np.delete(sharp_peaks_over,j , 0)
    piks.at[i, 'Sharp peaks'] = len(sharp_peaks_over)



# create features.csv
parent_dir = os.getcwd()
piks.to_csv(os.path.join(parent_dir, "Peaks.csv"))
