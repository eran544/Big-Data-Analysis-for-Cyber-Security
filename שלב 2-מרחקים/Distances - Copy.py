import numpy as np
import pandas as pd
import os
import matplotlib.dates as md
import matplotlib.pyplot as plt
import pandas as pd
from collections import deque
from scipy import ndimage
from dtw import dtw


# Gets "clean files day data.csv"
# retruen distances


class maxDistances:
    def __init__(self, num_files, K):
        self.k = K
        self.num_files = num_files
        self.data = [[(0, 0, 0) for _ in range(K)] for _ in range(num_files)]

    def insert(self, fileIndex, value):
        (distance, id, malicous) = value
        if (self.data[fileIndex][self.k - 1][0] >= value[0]):
            return False
        else:
            self.data[fileIndex].pop()
            for i in range(self.k - 1):
                if (self.data[fileIndex][i][0] < value[0]):
                    break;
        self.data[fileIndex].insert(i, value)
        assert (len(self.data[fileIndex]) == self.k)
        return True

    def print(self):
        for i in range(self.num_files):
            print("{0}. {1}\n".format(i, self.data[i]))


def recenter(arr, arr_center):
    items = deque(arr)
    for i in range(len(arr)):
        items.append(0)
    items.rotate(len(arr) - int(arr_center))
    return np.array(items)





cleanDay = pd.read_csv("clean files day data.csv")[["Sha1ID", "day_Array", "Malicious"]]
malDay = pd.read_csv("malicious files day data.csv")[["Sha1ID", "day_Array", "Malicious"]]

kbest_clean_Euclidean: maxDistances = maxDistances(len(malDay), 3)
kbest_clean_DTW = maxDistances(len(malDay), 3)

for i in range(0, len(malDay)):
    id1 = malDay.iloc[i]["Sha1ID"]
    mal1 = malDay.iloc[i]["Malicious"]
    for j in range(i + 1, len(malDay)):
        id2 = malDay.iloc[j]["Sha1ID"]
        mal2 = malDay.iloc[j]["Malicious"]

        a = malDay["day_Array"][i]
        a = map(int, list(a[1:-1].split()))
        a = np.array([int(s) for s in a])
        b = malDay["day_Array"][j]
        b = map(int, list(b[1:-1].split()))
        b = np.array([int(s) for s in b])
        # -------- Centerized Euclidean distance:----------------
        a_center = ndimage.measurements.center_of_mass(a)[0]
        b_center = ndimage.measurements.center_of_mass(b)[0]
        a_recenter = recenter(a, a_center)
        b_recenter = recenter(b, b_center)
        # print("Centerized Euclidean distance for files", cleanDay.iloc[i]["Sha1ID"], cleanDay.iloc[j]["Sha1ID"])
        # print(np.linalg.norm(a_recenter - b_recenter))
        res = (np.linalg.norm(a_recenter - b_recenter))
        kbest_clean_Euclidean.insert(i, (res, id2, mal2))
        kbest_clean_Euclidean.insert(j, (res, id1, mal1))

        # ------ DTW:----------
        x = a.reshape(-1, 1)  # reshape to make it work
        y = b.reshape(-1, 1)
        l2_norm = lambda x, y: (x - y) ** 2  # Here, we use L2 norm as the element comparison distance
        d, cost_matrix, acc_cost_matrix, path = dtw(x, y, dist=l2_norm)
        # print("DTW:", d)
        kbest_clean_DTW.insert(i, (res, id2, mal2))
        kbest_clean_DTW.insert(j, (res, id1, mal1))
    # if (i==4 or i==8):
    #     print("---------------{0}---------\n".format(i))
    #     kbest_clean_Euclidean.print()
    #     kbest_clean_DTW.print()
