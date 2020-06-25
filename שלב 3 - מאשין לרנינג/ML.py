import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn import svm, datasets, metrics

def machine_learning():
    df=pd.read_csv('features.csv')
    #df.head(20)
    #df['Size'] = df.index
    sns.countplot(x='Size', data=df)
    size = pd.get_dummies(df['Size'], drop_first=True)
    forML = df[['Malicious', 'Size', 'DTW k-Malicious(%)']]
    #forML = pd.concat([forML, size], axis=1)
    DTW = pd.get_dummies(df['DTW k-Malicious(%)'], drop_first=True)
    #forML = pd.concat([forML, DTW], axis=1)
    forML.info()
    forML.head()
    #forML.columns()


    X_train, X_test, Y_train, Y_test = train_test_split(forML.drop('Malicious', axis = 1), forML['Malicious'],
                                                        test_size=0.30, random_state=101)
    logmodel = LogisticRegression(penalty='l1',  # l2 and l2
                                  solver='liblinear',
                                  max_iter=50, )
    result = logmodel.fit(X_train, Y_train)
    probs = logmodel.predict_proba(X_test)
    preds = probs[:,1]
    # print(preds)
    fpr, tpr, threshold = metrics.roc_curve(Y_test, preds)
    roc_auc = metrics.auc(fpr, tpr)
    plt.title('Receiver Operating Characteristic')
    plt.plot(fpr, tpr, 'b', label='AUC = %0.2f' % roc_auc)
    plt.legend(loc='lower right')
    plt.plot([0, 1], [0, 1], 'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.show()
    print('finished')

machine_learning()


