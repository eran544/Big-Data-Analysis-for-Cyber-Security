from typing import List

import math
import statistics
import numpy as np
import pandas as pd
from collections import deque
from scipy import ndimage
from dtw import dtw
import csv


import matplotlib.dates as md
import matplotlib.pyplot as plt
import os
# Gets "clean files day data.csv"
# return distances

class minDistances:

    def __init__(self, num_files, K):
        self.k = K
        self.num_files = num_files
        self.min_data = [[(float('Inf'), 0, 0) for _ in range(K)] for _ in range(num_files)]      #k-min distances per file
        self.distances = [[float('Inf') for _ in range(num_files)] for _ in range(num_files)]      #distance per file
        self.all_data = []      #distance of all files
        # self.mean_distances_min = []
        # self.std_distances_min = []
        self.statistics = []

    def insert_distances(self, i, j, value):
        self.distances[i][j]= value
        self.distances[j][i]= value

    def insert(self, fileIndex, value):
        (distance, id, malicious) = value
        if (self.min_data[fileIndex][self.k - 1][0] <= value[0]):
            return False
        else:
            for i in range(self.k ):
                if (self.min_data[fileIndex][i][0] > value[0]):
                    break;
        self.min_data[fileIndex].insert(i, value)
        self.min_data[fileIndex].pop()
        assert (len(self.min_data[fileIndex]) == self.k)
        return True

    def print_min(self):
        for i in range(self.num_files):
            print("file {0}: {1}\n".format(cleanDay["Sha1ID"][i], self.min_data[i]))

    def print_all(self):
        for i in range(len(self.all_data)):
            print("{0}. {1}\n".format(i, self.all_data[i]))

    def get_Kbest_info(self, fileIndex):
        dist=[]
        isMal=[]
        for (distance, id, malicious) in  self.min_data[fileIndex]:
            dist.append(distance)
            isMal.append(malicious)
        return (dist,isMal)

    def calc_statisics(self):
        if(self.statistics==[]):
            self.statistics = pd.DataFrame([],  columns=["k best distances","k is malicius","k's mean","k's median", "k's std","k's malicios percentage","k's clean percentage","all's mean", "all's median","all's std_i"])
            stats=[]
            for i in range(self.num_files):
                #-----k best----
                (k_dist, k_isMal) = self.get_Kbest_info(i)
                k_mean_i= np.mean(k_dist)
                k_median_i = np.median(k_dist)
                k_std_i =np.std(k_dist)
                k_mal_precent=k_isMal.count(True)*100/self.k
                k_clean_precent = k_isMal.count(False) * 100 / self.k

                # -----all data----
                all_dist_i = self.distances[i]
                all_dist_i[i]=0 #remove inf in dist(self,self)
                all_dist_mean = np.mean(all_dist_i)
                all_dist_median_i = np.median(all_dist_i)
                all_dist_std_i = np.std(all_dist_i)
                max_dist=max(all_dist_i)
                min_dist=k_dist[0]

                data_for_file = pd.DataFrame([[k_dist,k_isMal,k_mean_i,k_median_i, k_std_i,k_mal_precent,k_clean_precent, all_dist_mean, all_dist_median_i, all_dist_std_i,max_dist,min_dist]],
                                             columns=["k best distances","k is malicius","k's mean","k's median",
                                                      "k's std","k's malicios percentage","k's clean percentage","all's mean", "all's median","all's std_i","max dist","min dist"])
                self.statistics = self.statistics.append(data_for_file, ignore_index=True)
        return self.statistics
def recenter(arr, arr_center):
    items = deque(arr)
    for i in range(len(arr)):
        items.append(0)
    items.rotate(len(arr) - int(arr_center))
    return np.array(items)


k = 3
cleanDay=pd.read_csv("clean files day data.csv")[["Sha1ID", "day_Array", "Malicious"]]
malnDay = pd.read_csv("malicious files day data.csv")[["Sha1ID", "day_Array", "Malicious"]]

kbest_clean_Euclidean = minDistances(len(cleanDay), 3)
kbest_clean_DTW = minDistances(len(cleanDay), 3)

sum_euclidian = 0
sum_dtw = 0
counter = 0
z = 0
for i in range(0, len(cleanDay)):
    id1 = cleanDay.iloc[i]["Sha1ID"]
    mal1 = cleanDay.iloc[i]["Malicious"]

    for j in range(i + 1, len(cleanDay)):
        id2 = cleanDay.iloc[j]["Sha1ID"]
        mal2 = cleanDay.iloc[j]["Malicious"]

        a = cleanDay["day_Array"][i]
        a = map(int, list(a[1:-1].split()))
        a = np.array([int(s) for s in a])
        b = cleanDay["day_Array"][j]
        b = map(int, list(b[1:-1].split()))
        b = np.array([int(s) for s in b])
        if sum(a) <= 2 or sum(b) <= 2:
            z = z + 1
            break
        # -------- Centerized Euclidean distance:----------------
        a_center = ndimage.measurements.center_of_mass(a)[0]
        b_center = ndimage.measurements.center_of_mass(b)[0]

        a_recenter = recenter(a, a_center)
        b_recenter = recenter(b, b_center)
        # print("Centerized Euclidean distance for files", cleanDay.iloc[i]["Sha1ID"], cleanDay.iloc[j]["Sha1ID"])
        # print(np.linalg.norm(a_recenter - b_recenter))
        res=(np.linalg.norm(a_recenter - b_recenter))
        kbest_clean_Euclidean.insert(i,(res,id2,mal2))
        kbest_clean_Euclidean.insert(j,(res,id1,mal1))

        kbest_clean_Euclidean.insert_distances(i, j, res)
        kbest_clean_Euclidean.all_data.append(res)

        sum_euclidian = sum_euclidian + res
        # ------ DTW:----------
        x = a.reshape(-1, 1)  # reshape to make it work
        y = b.reshape(-1, 1)
        l2_norm = lambda x, y: (x - y) ** 2  # Here, we use L2 norm as the element comparison distance
        d, cost_matrix, acc_cost_matrix, path = dtw(x, y, dist=l2_norm)
        # print("DTW:", d)
        kbest_clean_DTW.insert(i, (d, id2, mal2))
        kbest_clean_DTW.insert(j, (d, id1, mal1))

        kbest_clean_DTW.insert_distances(i, j, d)
        sum_dtw = sum_dtw + d
        kbest_clean_DTW.all_data.append(d)

        counter = counter + 1

# --------- write to csv --------
# f = open('Euclidian.csv', 'w')
#
# with f:
#     writer = csv.writer(f)
#     for row in kbest_clean_Euclidian.distances:
#         writer.writerow(row)

# f = open('DTW.csv', 'w')
#
# with f:
#     writer = csv.writer(f)
#     for row in kbest_clean_DTW.distances:
#         writer.writerow(row)

# --------- print lists ---------
# kbest_clean_Euclidean.print_min()
# kbest_clean_DTW.print_min()
# kbest_clean_Euclidean.print_all()
# kbest_clean_DTW.print_all()

# # --------- statistics per file ---------
# sum_average = 0
# i = 0
# print("-------------- EUCLIDIAN: --------------")
# for row in kbest_clean_Euclidean.distances:
#     average = sum(row) / 108
#     print("file {0}: \nAverage: {1}".format(cleanDay["Sha1ID"][i], average))
#     print("STD: ", statistics.pstdev(row))
#     sum_average = sum_average + average
#     i = i + 1
#     print("\n")
#
# print("-------------- DTW: --------------")
#
# sum_average = 0
# i = 0
# for row in kbest_clean_DTW.distances:
#     average = sum(row) / 108
#     print("file {0}: \nAverage: {1}".format(cleanDay["Sha1ID"][i], average))
#     print("STD: ", statistics.pstdev(row))
#     sum_average = sum_average + average
#     i = i + 1
#     print("\n")

# ----------------------------- statistics all files --------------------
all_stat=data_for_file=pd.DataFrame([],columns=["name", "mean", "median",  "std", "max", "min"])
#---------- Euclidean: ------------
Euclidean_statistics=kbest_clean_Euclidean.calc_statisics()
Euclidian_average = sum_euclidian / counter
Euclidian_std=kbest_clean_Euclidean.all_data
Euclidian_median=statistics.median(kbest_clean_Euclidean.all_data)
Euclidian_Min=min(Euclidean_statistics["min dist"])
Euclidian_Max=max(Euclidean_statistics["max dist"])

data_for_file = pd.DataFrame([["Euclidian",Euclidian_average, Euclidian_median, Euclidian_std, Euclidian_Max, Euclidian_Min]],
                             columns=["name", "mean", "median",  "std", "max", "min"])
all_stat = all_stat.append(data_for_file, ignore_index=True)

#---------- DTW: ------------
DTW_statistics=kbest_clean_DTW.calc_statisics()
DTW_average = sum_dtw / counter
DTW_std=statistics.pstdev(kbest_clean_DTW.all_data)
DTW_median=statistics.median(kbest_clean_DTW.all_data)
DTW_Min=min(DTW_statistics["min dist"])
DTW_Max=max(DTW_statistics["max dist"])
data_for_file = pd.DataFrame([["DTW",DTW_average,DTW_median, DTW_std,DTW_Max, DTW_Min]],
                             columns=["name", "mean", "median",  "std", "max", "min"])
all_stat = all_stat.append(data_for_file, ignore_index=True)


print(z, "files were skipped")


parent_dir = os.getcwd()
all_stat.to_csv(os.path.join(parent_dir, "all data's statistics.csv"))
Euclidean_statistics.to_csv(os.path.join(parent_dir, "Euclidean Distances.csv"))
DTW_statistics.to_csv(os.path.join(parent_dir, "DTW Distances.csv"))



print("finished")

