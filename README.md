# <b> Big Data Analysis for Cyber Security: Time-Series Analysis mini project </b>


### <i> This project's main goal is to train a classifier who can detect malicious files.<br>                                        We detected patterns of clean files versus malicious files in our dataset using time series analysis and pattern extraction methods, and trained a classifier accordingly using machine learning. 
### <i> The dataset we based our work on has been provided us by Microsoft and includes information about downloaded files sent as a webmail attachment in the first 14 days of 2017.
### <i> The project in wiritten in Python, using pandas library for data analysis and sklearn library for machine learning algorithms.
<hr>


## Step One - Preliminary analysis of the data
We divided the dataset into two groups, train- the first 11 days of the dataset, and test-the remaining 3 days of the dataset.

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/1.JPG)

First, we set a threshold for files - a file will be removed if it had 5 or less downloads on different machines. 

This means that a file is defined as clean if it is not tagged as malicious during the entire test period, and also has more
than 5 downloads on different machines. 
A file is defined as malicious if it is tagged as malicious in one of its instances during the train period, and has more than 5 downloads on different machines.

Having set the threshold above, this is the data we have left which meets the definition:

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/2.jpg)

see code at: <br>
https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/TRAIN/TRAIN%20DATA/All_data_to_Hour_Day_datasets.py

For each file from the train group we created a time series (vector representing number of downloads in a (daily / hourly time frame ) that represents the number of file downloads on different machines, ie does not include repeated downloads of a file on the same machine.
To produce time series - we started by classifying by day and by hour: we grouped the downloads for each file => We deleted double downloads on the same machine according to SH1 so that for each day / hour we left the first download that occurred on a specific machine only.

We started with a division of time ranges by hours and by days. Later we decided to continue with time series at intervals of only days (for technical reasons of code execution times).

Example for dayly time series of a file:
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/3.jpg)

see code at: <br>
https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/TRAIN/TRAIN%20DATA/Dayset_to_day_data.py



## Step Two - Calculating File distances
For each file from the data set we calculated the distance between its time series and all the other files time serieses in both methods.


### 1. Euclidean distance: 
Given two time series 
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/time.JPG)

we get the Euclidean distance between them by the following calculation: <br>
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/ouc.JPG)

In addition, we performed a preliminary calculation of the change in the center of mass so that each series would start from the first number that is not 0, by performing a circular shift - transferring a prime of 0 to the end of the series. This calculation is intended so that patterns of increase / decrease in the rate of the number of downloads can also be identified at different times.

### 2. Dynamic Time Wrapping (DTW) Algorithm:
given two series, seeks the best match between them by the following formula: <br>
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/dtw.JPG)
meaning it matches the patterns in the download rate and then compares them.

see code at: <br>
https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/TRAIN/TRAIN%20DATA/Distances.py



## Step three- Features Analysis
For each file we have selected a number of properties, wich we will pass to the ML model to distinguish between clean and malicious files. For each file we extracted three types of properties  :

### 1. Prevalence feature - file download frequency, total downloads on different machines each day.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/PREVALENCE.jpg)

### 2. Size - File size in KB.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/SIZE.png)

### 3. DTW / Euclidean 5/10/15 Malicious- Represents the percentage of malicious files out of the 5/10/15 files closest to each file in each method.<br>
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/K5.png) <br>

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/K10.png)<br>

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/k15.JPG)

### 4. Day Count Mean- Indicates the average daily downloads of the files.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/MEAN.jpg)

### 5. Peaks- Indicates the number of days in the time series in which the number of downloads exceeded 3.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/PEAKS.jpg)

### 6. Sharp Peaks- Indicates the number of days in the time series in which the difference between the number of downloads in that day and the downloads in its surrounding exceeds 15.<br> We used a topographic  prominence algorithm to find peakes that stand out above their surrounding.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/SHARPPEAKS.tif.jpg)

### 7. Day Count STD- Indicates the standard deviation of the number of downloads per day.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/STD.jpg)

### 8. Max Day Count- Displays the distribution of the maximum number of downloads in each time series for each file.
![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/MAX.png)

see code at: <br>
https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/TRAIN/TRAIN%20DATA/features.py



## Step Four - Machine Learning
We trained two types of models - Logistic Regression and TreeClassifier on the train dataset.<br> We ran 5-Fold Cross Validation on each of the models.
The score of each model is determined by the average of the scores of the runs.<br> The highest score was obtained for tree model with a depth equal to 3.

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/5FOLD.jpg)

After running the selected model on the test dataset on the we can see the importance of each characteristic.

The coefficient of each feature represents the correlation between it and the classification of the file as malicious by the model.

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/FEATURES.jpg)

### Model results for each distance calculation method:

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/RES1.png)

![](https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/results/images/RES2.png)

see code at:<br>
https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/ML/DTW%20ML/ML.py

https://github.com/eran544/Big-Data-Analysis-for-Cyber-Security/blob/master/ML/Euclidean%20ML/ML.py



## Step Five - Conclusions
The models we used provided a very different picture than we expected.

On the contrary to the assumption we had in the beginning that DTW will provide more accurate results, it turned out that the Euclidean distance method yielded better results in the AUC index.

In addition, in contrast to the expectation that the characteristics associated with the calculation of downloads "peaks" would have significant weight in the classification of the file, these characteristics were found to be of the least importance. 

Unfortunately, the weight of the features obtained did not provide the desired result at all and could not provide us a strong and clear picture as to the classification of the files.
Perhaps in order to see differences in download patterns with these features, it is necessary to increase the amount of files in the dataset and / or the measured time frame.

